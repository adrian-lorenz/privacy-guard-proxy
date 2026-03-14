// Package api provides a privacy-guard-compatible HTTP API backed by built-in detectors.
//
// Endpoints:
//
//	GET  /health    → {"status":"ok"}
//	POST /anonymize → {"text":"..."} → {"anonymised_text":"..."}
//	POST /scan      → {"text":"..."} → full findings + mapping
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/adrian-lorenz/privacy-guard-proxy/internal/detector"
)

// Run starts the API server on the given port. Blocks until error.
func Run(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /anonymize", handleAnonymize)
	mux.HandleFunc("POST /scan", handleScan)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	slog.Info("privacy-guard API listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("API server error", "err", err)
	}
}

// ─── Request / Response types ─────────────────────────────────────────────────

type request struct {
	Text      string   `json:"text"`
	Detectors []string `json:"detectors,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
}

type anonymizeResponse struct {
	AnonymisedText string `json:"anonymised_text"`
}

type finding struct {
	Type        string  `json:"pii_type"`
	Start       int     `json:"start"`
	End         int     `json:"end"`
	Text        string  `json:"text"`
	Confidence  float64 `json:"confidence"`
	Placeholder string  `json:"placeholder"`
	RuleID      string  `json:"rule_id,omitempty"`
}

type scanResponse struct {
	OriginalText   string            `json:"original_text"`
	AnonymisedText string            `json:"anonymised_text"`
	Findings       []finding         `json:"findings"`
	Mapping        map[string]string `json:"mapping"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func handleAnonymize(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	anonymised, _ := detector.NewScanner(req.Detectors).Scan(req.Text)
	writeJSON(w, anonymizeResponse{AnonymisedText: anonymised})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	anonymised, findings := detector.NewScanner(req.Detectors).Scan(req.Text)

	apiFindings := make([]finding, len(findings))
	mapping := map[string]string{}
	for i, f := range findings {
		apiFindings[i] = finding{
			Type:        string(f.Type),
			Start:       f.Start,
			End:         f.End,
			Text:        f.Text,
			Confidence:  f.Confidence,
			Placeholder: f.Placeholder,
			RuleID:      f.RuleID,
		}
		if f.Placeholder != "" {
			mapping[f.Placeholder] = f.Text
		}
	}

	writeJSON(w, scanResponse{
		OriginalText:   req.Text,
		AnonymisedText: anonymised,
		Findings:       apiFindings,
		Mapping:        mapping,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("failed to encode response", "err", err)
	}
}
