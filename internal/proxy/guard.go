package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"

	"github.com/adrian-lorenz/privacy-guard-proxy/internal/detector"
)

// ScanSummary describes what was found and masked in a single Apply call.
type ScanSummary struct {
	PIIFound     int      `json:"pii_found"`
	Placeholders []string `json:"placeholders"`
	IsJSON       bool     `json:"is_json"`
}

func emptySummary() ScanSummary  { return ScanSummary{} }
func binarySummary() ScanSummary { return ScanSummary{Placeholders: []string{"<binary>"}} }

// Guard applies PII masking to HTTP request bodies using built-in detectors.
type Guard struct {
	config  GuardConfig
	scanner *detector.Scanner
}

// NewGuard creates a Guard from a GuardConfig.
func NewGuard(cfg GuardConfig) *Guard {
	return &Guard{
		config:  cfg,
		scanner: detector.NewScanner(cfg.Detectors),
	}
}

// Apply masks PII in body. upstreamType controls which JSON fields are targeted.
func (g *Guard) Apply(body []byte, upstreamType string) ([]byte, ScanSummary) {
	if len(body) == 0 {
		return body, emptySummary()
	}
	if !isValidUTF8(body) {
		return body, binarySummary()
	}

	var jsonBody map[string]any
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		var summary ScanSummary
		switch upstreamType {
		case "claude-code":
			summary = g.anonymiseClaudeCode(jsonBody)
		default:
			summary = g.anonymiseClaudeCode(jsonBody)
		}
		masked, err := json.Marshal(jsonBody)
		if err != nil {
			masked = body
		}
		return masked, summary
	}

	masked := g.mask(string(body), "raw-body")
	return []byte(masked), ScanSummary{IsJSON: false}
}

// anonymiseClaudeCode masks PII in user messages only.
// The system prompt is intentionally skipped — it contains model instructions,
// not user PII, and masking it corrupts tool names / model identity.
func (g *Guard) anonymiseClaudeCode(j map[string]any) ScanSummary {
	masked := 0
	if msgs, ok := j["messages"]; ok {
		if arr, ok := msgs.([]any); ok {
			for _, msg := range arr {
				if msgMap, ok := msg.(map[string]any); ok {
					if role, _ := msgMap["role"].(string); role == "user" {
						if g.anonymiseMessageContent(msgMap) {
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

func (g *Guard) anonymiseMessageContent(msg map[string]any) bool {
	content, ok := msg["content"]
	if !ok {
		return false
	}
	changed := false
	switch c := content.(type) {
	case string:
		if m := g.mask(c, "message.content"); m != c {
			msg["content"] = m
			changed = true
		}
	case []any:
		for _, part := range c {
			if partMap, ok := part.(map[string]any); ok {
				if g.anonymiseContentBlock(partMap) {
					changed = true
				}
			}
		}
	}
	return changed
}

func (g *Guard) anonymiseContentBlock(block map[string]any) bool {
	changed := false
	switch block["type"] {
	case "text":
		if s, ok := block["text"].(string); ok {
			if m := g.mask(s, "text"); m != s {
				block["text"] = m
				changed = true
			}
		}
	case "tool_result":
		switch v := block["content"].(type) {
		case string:
			if m := g.mask(v, "tool_result"); m != v {
				block["content"] = m
				changed = true
			}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					if s, ok := m["text"].(string); ok {
						if masked := g.mask(s, "tool_result part"); masked != s {
							m["text"] = masked
							changed = true
						}
					}
				}
			}
		}
	case "tool_use":
		if input, ok := block["input"].(map[string]any); ok {
			if g.anonymiseStringValues(input) {
				changed = true
			}
		}
	}
	return changed
}

func (g *Guard) anonymiseStringValues(m map[string]any) bool {
	changed := false
	for k, v := range m {
		switch val := v.(type) {
		case string:
			if masked := g.mask(val, "tool_use.input."+k); masked != val {
				m[k] = masked
				changed = true
			}
		case map[string]any:
			if g.anonymiseStringValues(val) {
				changed = true
			}
		}
	}
	return changed
}

func (g *Guard) mask(text, label string) string {
	if text == "" {
		return text
	}
	masked, _ := g.scanner.Scan(text)
	if masked != text {
		slog.Info("PII masked", "label", label, "masked", masked)
	}
	return masked
}

func isValidUTF8(b []byte) bool {
	return bytes.Equal([]byte(string(b)), b) || len(b) == 0
}
