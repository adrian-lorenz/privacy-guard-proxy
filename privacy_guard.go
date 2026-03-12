package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// PrivacyGuardConfig holds the privacy-guard service configuration.
type PrivacyGuardConfig struct {
	URL       string   `json:"url"`
	APIKey    *string  `json:"api_key"`
	Detectors []string `json:"detectors"`
	Whitelist []string `json:"whitelist"`
}

// ScanSummary describes what was found and masked.
type ScanSummary struct {
	PIIFound     int      `json:"pii_found"`
	Placeholders []string `json:"placeholders"`
	IsJSON       bool     `json:"is_json"`
}

func emptySummary() ScanSummary  { return ScanSummary{} }
func binarySummary() ScanSummary { return ScanSummary{Placeholders: []string{"<binary>"}} }
func errorSummary(msg string) ScanSummary {
	return ScanSummary{Placeholders: []string{"ERROR: " + msg}}
}

// scanRequest is sent to the privacy-guard /scan endpoint.
type scanRequest struct {
	Text      string   `json:"text"`
	Detectors []string `json:"detectors,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
}

// anonymizeResponse is returned by privacy-guard /anonymize.
type anonymizeResponse struct {
	AnonymisedText string `json:"anonymised_text"`
}

// PrivacyGuard applies PII masking to request bodies.
type PrivacyGuard struct {
	client  *http.Client
	config  PrivacyGuardConfig
	scanURL string
}

func NewPrivacyGuard(cfg PrivacyGuardConfig) *PrivacyGuard {
	return &PrivacyGuard{
		client:  &http.Client{Timeout: 10 * time.Second},
		config:  cfg,
		scanURL: strings.TrimRight(cfg.URL, "/") + "/anonymize",
	}
}

// Apply masks PII in the body. upstreamType controls which JSON fields are anonymised.
func (pg *PrivacyGuard) Apply(body []byte, upstreamType string) ([]byte, ScanSummary) {
	if len(body) == 0 {
		return body, emptySummary()
	}
	if !isValidUTF8(body) {
		return body, binarySummary()
	}
	raw := string(body)

	var jsonBody map[string]any
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		var summary ScanSummary
		switch upstreamType {
		case "claude-code":
			summary = pg.anonymiseClaudeCode(jsonBody)
		default:
			summary = pg.anonymiseClaudeCode(jsonBody) // sensible fallback
		}
		masked, err := json.Marshal(jsonBody)
		if err != nil {
			masked = body
		}
		return masked, summary
	}

	resp, err := pg.callScan(raw)
	if err != nil {
		slog.Warn("privacy-guard call failed — forwarding unmasked", "err", err)
		return body, errorSummary(err.Error())
	}
	return []byte(resp.AnonymisedText), ScanSummary{IsJSON: false}
}

// anonymiseClaudeCode handles Anthropic API requests (messages only).
// The system prompt is intentionally skipped — it contains model instructions,
// not user PII, and masking it corrupts tool names / model identity.
func (pg *PrivacyGuard) anonymiseClaudeCode(j map[string]any) ScanSummary {
	masked := 0
	if msgs, ok := j["messages"]; ok {
		if arr, ok := msgs.([]any); ok {
			for _, msg := range arr {
				if msgMap, ok := msg.(map[string]any); ok {
					// only mask user messages, not assistant turns
					if role, _ := msgMap["role"].(string); role == "user" {
						if pg.anonymiseMessageContent(msgMap) {
							masked++
						}
					}
				}
			}
		}
	}
	slog.Info("masking done", "user_messages_masked", masked)
	return ScanSummary{PIIFound: masked, IsJSON: true}
}

// anonymiseMessageContent masks PII in a single message's content.
// Returns true if any text was changed.
func (pg *PrivacyGuard) anonymiseMessageContent(msg map[string]any) bool {
	content, ok := msg["content"]
	if !ok {
		return false
	}
	changed := false

	switch c := content.(type) {
	case string:
		if masked, ok := pg.mask(c, "message.content"); ok && masked != c {
			msg["content"] = masked
			changed = true
		}

	case []any:
		for _, part := range c {
			if partMap, ok := part.(map[string]any); ok {
				if pg.anonymiseContentBlock(partMap) {
					changed = true
				}
			}
		}
	}
	return changed
}

// anonymiseContentBlock handles a single content block (text, tool_use, tool_result).
func (pg *PrivacyGuard) anonymiseContentBlock(block map[string]any) bool {
	changed := false
	switch block["type"] {
	case "text":
		if s, ok := block["text"].(string); ok {
			if masked, ok := pg.mask(s, "text"); ok && masked != s {
				block["text"] = masked
				changed = true
			}
		}

	case "tool_result":
		switch v := block["content"].(type) {
		case string:
			if masked, ok := pg.mask(v, "tool_result"); ok && masked != v {
				block["content"] = masked
				changed = true
			}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					if s, ok := m["text"].(string); ok {
						if masked, ok := pg.mask(s, "tool_result part"); ok && masked != s {
							m["text"] = masked
							changed = true
						}
					}
				}
			}
		}

	case "tool_use":
		if input, ok := block["input"].(map[string]any); ok {
			if pg.anonymiseStringValues(input) {
				changed = true
			}
		}
	}
	return changed
}

// anonymiseStringValues recursively masks all string values in a map.
func (pg *PrivacyGuard) anonymiseStringValues(m map[string]any) bool {
	changed := false
	for k, v := range m {
		switch val := v.(type) {
		case string:
			if masked, ok := pg.mask(val, "tool_use.input."+k); ok && masked != val {
				m[k] = masked
				changed = true
			}
		case map[string]any:
			if pg.anonymiseStringValues(val) {
				changed = true
			}
		}
	}
	return changed
}

// mask calls the privacy-guard and returns the anonymised text.
func (pg *PrivacyGuard) mask(text, label string) (string, bool) {
	if text == "" {
		return text, true
	}
	resp, err := pg.callScan(text)
	if err != nil {
		slog.Warn("privacy-guard failed", "label", label, "err", err)
		return text, false
	}
	if resp.AnonymisedText != text {
		slog.Info("PII masked", "label", label, "masked", resp.AnonymisedText)
	}
	return resp.AnonymisedText, true
}

func (pg *PrivacyGuard) callScan(text string) (*anonymizeResponse, error) {
	slog.Debug("calling privacy-guard", "chars", len(text))

	req := scanRequest{
		Text:      text,
		Detectors: pg.config.Detectors,
		Whitelist: pg.config.Whitelist,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, pg.scanURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if pg.config.APIKey != nil {
		httpReq.Header.Set("X-API-Key", *pg.config.APIKey)
	}

	resp, err := pg.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("privacy-guard returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result anonymizeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func isValidUTF8(b []byte) bool {
	return bytes.Equal([]byte(string(b)), b) || len(b) == 0
}
