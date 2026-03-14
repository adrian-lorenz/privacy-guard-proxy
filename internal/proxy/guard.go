package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"

	"github.com/adrian-lorenz/privacy-guard-proxy/internal/detector"
)

// ScanSummary describes what was found and masked in a single Apply call.
type ScanSummary struct {
	PIIFound     int      `json:"pii_found"`
	Placeholders []string `json:"placeholders"`
	PIITypes     []string `json:"pii_types"`
	IsJSON       bool     `json:"is_json"`
	MaskedBytes  int      `json:"masked_bytes"`
}

func emptySummary() ScanSummary  { return ScanSummary{} }
func binarySummary() ScanSummary { return ScanSummary{Placeholders: []string{"<binary>"}} }

// Guard applies PII masking to HTTP request bodies using built-in detectors.
// Its configuration can be updated at runtime without restarting the proxy.
type Guard struct {
	mu      sync.RWMutex
	scanner *detector.Scanner
	cfg     GuardConfig
}

// NewGuard creates a Guard from a GuardConfig.
func NewGuard(cfg GuardConfig) *Guard {
	return &Guard{
		scanner: detector.NewScanner(cfg.Detectors),
		cfg:     cfg,
	}
}

// UpdateConfig swaps the scanner for a new one built from cfg.
// Safe for concurrent use — in-flight requests complete with the old scanner.
func (g *Guard) UpdateConfig(cfg GuardConfig) {
	g.mu.Lock()
	g.scanner = detector.NewScanner(cfg.Detectors)
	g.cfg = cfg
	g.mu.Unlock()
}

// Apply masks PII in body. upstreamType controls which JSON fields are targeted.
func (g *Guard) Apply(body []byte, upstreamType string) ([]byte, ScanSummary) {
	if len(body) == 0 {
		return body, emptySummary()
	}
	if !isValidUTF8(body) {
		return body, binarySummary()
	}

	g.mu.RLock()
	cfg := g.cfg
	sc := g.scanner
	g.mu.RUnlock()
	if cfg.DryRun {
		_, findings := sc.ScanWithWhitelist(string(body), cfg.Whitelist)
		return body, ScanSummary{
			PIIFound:     len(findings),
			PIITypes:     uniqueSortedFindingTypes(findings),
			Placeholders: uniquePlaceholders(findings),
			IsJSON:       false,
			MaskedBytes:  0,
		}
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
		if len(body) > len(masked) {
			summary.MaskedBytes = len(body) - len(masked)
		}
		return masked, summary
	}

	masked, findings := g.maskWithTypes(string(body), "raw-body")
	summary := ScanSummary{
		PIIFound:     len(findings),
		PIITypes:     findingTypes(findings),
		Placeholders: uniquePlaceholders(findings),
		IsJSON:       false,
	}
	if len(body) > len(masked) {
		summary.MaskedBytes = len(body) - len(masked)
	}
	return []byte(masked), summary
}

// anonymiseClaudeCode masks PII in user messages only.
// The system prompt is intentionally skipped — it contains model instructions,
// not user PII, and masking it corrupts tool names / model identity.
func (g *Guard) anonymiseClaudeCode(j map[string]any) ScanSummary {
	maskedMsgs := 0
	var allFindings []detector.Finding
	if msgs, ok := j["messages"]; ok {
		if arr, ok := msgs.([]any); ok {
			for _, msg := range arr {
				if msgMap, ok := msg.(map[string]any); ok {
					if role, _ := msgMap["role"].(string); role == "user" {
						found, findings := g.anonymiseMessageContentWithTypes(msgMap)
						if found {
							maskedMsgs++
						}
						allFindings = append(allFindings, findings...)
					}
				}
			}
		}
	}
	slog.Info("masking done", "user_messages_masked", maskedMsgs, "pii_findings", len(allFindings))
	return ScanSummary{
		PIIFound:     len(allFindings),
		PIITypes:     uniqueSortedFindingTypes(allFindings),
		Placeholders: uniquePlaceholders(allFindings),
		IsJSON:       true,
	}
}

func (g *Guard) anonymiseMessageContentWithTypes(msg map[string]any) (bool, []detector.Finding) {
	content, ok := msg["content"]
	if !ok {
		return false, nil
	}
	changed := false
	var findings []detector.Finding
	switch c := content.(type) {
	case string:
		m, fs := g.maskWithTypes(c, "message.content")
		if m != c {
			msg["content"] = m
			changed = true
			findings = append(findings, fs...)
		}
	case []any:
		for _, part := range c {
			if partMap, ok := part.(map[string]any); ok {
				found, fs := g.anonymiseContentBlockWithTypes(partMap)
				if found {
					changed = true
					findings = append(findings, fs...)
				}
			}
		}
	}
	return changed, findings
}

func (g *Guard) anonymiseContentBlockWithTypes(block map[string]any) (bool, []detector.Finding) {
	changed := false
	var findings []detector.Finding
	switch block["type"] {
	case "text":
		if s, ok := block["text"].(string); ok {
			m, fs := g.maskWithTypes(s, "text")
			if m != s {
				block["text"] = m
				changed = true
				findings = append(findings, fs...)
			}
		}
	case "tool_result":
		switch v := block["content"].(type) {
		case string:
			m, fs := g.maskWithTypes(v, "tool_result")
			if m != v {
				block["content"] = m
				changed = true
				findings = append(findings, fs...)
			}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					if s, ok := m["text"].(string); ok {
						masked, fs := g.maskWithTypes(s, "tool_result part")
						if masked != s {
							m["text"] = masked
							changed = true
							findings = append(findings, fs...)
						}
					}
				}
			}
		}
	case "tool_use":
		if input, ok := block["input"].(map[string]any); ok {
			found, fs := g.anonymiseStringValuesWithTypes(input)
			if found {
				changed = true
				findings = append(findings, fs...)
			}
		}
	}
	return changed, findings
}

func (g *Guard) anonymiseStringValuesWithTypes(m map[string]any) (bool, []detector.Finding) {
	changed := false
	var findings []detector.Finding
	for k, v := range m {
		switch val := v.(type) {
		case string:
			masked, fs := g.maskWithTypes(val, "tool_use.input."+k)
			if masked != val {
				m[k] = masked
				changed = true
				findings = append(findings, fs...)
			}
		case map[string]any:
			found, fs := g.anonymiseStringValuesWithTypes(val)
			if found {
				changed = true
				findings = append(findings, fs...)
			}
		}
	}
	return changed, findings
}

func (g *Guard) maskWithTypes(text, label string) (string, []detector.Finding) {
	if text == "" {
		return text, nil
	}
	g.mu.RLock()
	sc := g.scanner
	whitelist := g.cfg.Whitelist
	g.mu.RUnlock()
	masked, findings := sc.ScanWithWhitelist(text, whitelist)
	if masked != text {
		slog.Info("PII masked", "label", label, "masked", masked)
	}
	return masked, findings
}

func findingTypes(findings []detector.Finding) []string {
	var types []string
	for _, f := range findings {
		types = append(types, string(f.Type))
	}
	return types
}

func uniqueSortedFindingTypes(findings []detector.Finding) []string {
	seen := map[string]struct{}{}
	for _, f := range findings {
		seen[string(f.Type)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func uniquePlaceholders(findings []detector.Finding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Placeholder == "" {
			continue
		}
		if _, ok := seen[f.Placeholder]; ok {
			continue
		}
		seen[f.Placeholder] = struct{}{}
		out = append(out, f.Placeholder)
	}
	sort.Strings(out)
	return out
}

func isValidUTF8(b []byte) bool {
	return bytes.Equal([]byte(string(b)), b) || len(b) == 0
}
