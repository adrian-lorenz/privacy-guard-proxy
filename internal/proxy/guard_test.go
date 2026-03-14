package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func newTestGuard(detectors []string) *Guard {
	return NewGuard(GuardConfig{Detectors: detectors})
}

func TestGuardApplyEmptyBody(t *testing.T) {
	g := newTestGuard(nil)
	out, summary := g.Apply([]byte{}, "claude-code")
	if len(out) != 0 {
		t.Errorf("expected empty output, got %q", out)
	}
	_ = summary
}

func TestGuardApplyNonJSONBody(t *testing.T) {
	g := newTestGuard([]string{"EMAIL"})
	// Non-JSON plain text body — should be scanned as raw text
	body := []byte("Kontakt: raw@example.de (kein JSON)")
	out, summary := g.Apply(body, "claude-code")
	if strings.Contains(string(out), "raw@example.de") {
		t.Errorf("email in non-JSON body should be masked, got %s", out)
	}
	if summary.IsJSON {
		t.Error("expected IsJSON=false for plain text body")
	}
}

func TestGuardApplyMasksUserMessage(t *testing.T) {
	g := newTestGuard([]string{"EMAIL"})
	body := map[string]any{
		"messages": []any{
			map[string]any{
				"role":    "user",
				"content": "Schreib an kontakt@example.de",
			},
		},
	}
	data, _ := json.Marshal(body)
	out, summary := g.Apply(data, "claude-code")
	if strings.Contains(string(out), "kontakt@example.de") {
		t.Errorf("email should be masked in %s", out)
	}
	if summary.PIIFound == 0 {
		t.Error("expected PIIFound > 0")
	}
}

func TestGuardApplySkipsAssistantMessage(t *testing.T) {
	g := newTestGuard([]string{"EMAIL"})
	body := map[string]any{
		"messages": []any{
			map[string]any{
				"role":    "assistant",
				"content": "Deine Email ist kontakt@example.de",
			},
		},
	}
	data, _ := json.Marshal(body)
	out, _ := g.Apply(data, "claude-code")
	if !strings.Contains(string(out), "kontakt@example.de") {
		t.Error("assistant message should NOT be masked")
	}
}

func TestGuardApplySkipsSystemPrompt(t *testing.T) {
	g := newTestGuard(nil)
	body := map[string]any{
		"system": "You are a helpful assistant. Contact: support@anthropic.com",
		"messages": []any{
			map[string]any{"role": "user", "content": "Hello"},
		},
	}
	data, _ := json.Marshal(body)
	out, _ := g.Apply(data, "claude-code")
	if !strings.Contains(string(out), "support@anthropic.com") {
		t.Error("system prompt should NOT be masked")
	}
}

func TestGuardApplyMasksToolResult(t *testing.T) {
	g := newTestGuard([]string{"EMAIL"})
	body := map[string]any{
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "x",
						"content":     "Ergebnis: user@example.com",
					},
				},
			},
		},
	}
	data, _ := json.Marshal(body)
	out, _ := g.Apply(data, "claude-code")
	if strings.Contains(string(out), "user@example.com") {
		t.Errorf("email in tool_result should be masked, got %s", out)
	}
}

func TestGuardApplyPlainText(t *testing.T) {
	g := newTestGuard([]string{"EMAIL"})
	body := []byte("Kontakt: info@example.de")
	out, summary := g.Apply(body, "claude-code")
	if strings.Contains(string(out), "info@example.de") {
		t.Errorf("email in plain text body should be masked, got %s", out)
	}
	if summary.IsJSON {
		t.Error("plain text body should have IsJSON=false")
	}
}

func TestGuardApplySelectiveDetectors(t *testing.T) {
	// Only IBAN enabled — email must pass through
	g := newTestGuard([]string{"IBAN"})
	body := map[string]any{
		"messages": []any{
			map[string]any{
				"role":    "user",
				"content": "Email: info@example.de, IBAN: DE89 3704 0044 0532 0130 00",
			},
		},
	}
	data, _ := json.Marshal(body)
	out, _ := g.Apply(data, "claude-code")
	if !strings.Contains(string(out), "info@example.de") {
		t.Error("email should NOT be masked when only IBAN detector is active")
	}
	if strings.Contains(string(out), "DE89 3704 0044 0532 0130 00") {
		t.Error("IBAN should be masked")
	}
}

func TestGuardApplyWhitelist(t *testing.T) {
	g := NewGuard(GuardConfig{
		Detectors: []string{"EMAIL"},
		Whitelist: []string{"safe@example.com"},
	})
	body := []byte(`{"messages":[{"role":"user","content":"safe@example.com und risk@example.com"}]}`)
	out, summary := g.Apply(body, "claude-code")
	got := string(out)
	if !strings.Contains(got, "safe@example.com") {
		t.Fatalf("whitelisted email should remain: %s", got)
	}
	if strings.Contains(got, "risk@example.com") {
		t.Fatalf("non-whitelisted email should be masked: %s", got)
	}
	if summary.PIIFound != 1 {
		t.Fatalf("PIIFound=%d, want 1", summary.PIIFound)
	}
}

func TestGuardApplyPiiFoundCountsFindings(t *testing.T) {
	g := NewGuard(GuardConfig{Detectors: []string{"EMAIL", "PHONE"}})
	body := []byte(`{"messages":[{"role":"user","content":"a@example.com +49 171 1234567"}]}`)
	_, summary := g.Apply(body, "claude-code")
	if summary.PIIFound < 2 {
		t.Fatalf("PIIFound=%d, want >=2 findings", summary.PIIFound)
	}
}
