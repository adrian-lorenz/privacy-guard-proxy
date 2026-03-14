// Package api provides a privacy-guard-compatible HTTP API backed by built-in detectors.
//
// Endpoints:
//
//	GET  /health    → {"status":"ok"}
//	POST /anonymize → {"text":"..."} → {"anonymised_text":"..."}
//	POST /scan      → {"text":"..."} → full findings + mapping
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/adrian-lorenz/privacy-guard-proxy/internal/detector"
	"github.com/adrian-lorenz/privacy-guard-proxy/internal/proxy"
)

// ─── Runtime config ────────────────────────────────────────────────────────────

var (
	rtMu           sync.RWMutex
	rtKeyHashes    = map[string]struct{}{} // sha256(key) → exists
	rtDefDetectors []string
	rtDefWhitelist []string
	rtCORSOrigins  []string
	rtRateMu       sync.Mutex
	rtRateState    = map[string]rateWindow{}
)

type rateWindow struct {
	Minute int64
	Count  int
}

const apiRateLimitPerMinute = 120

func applyRuntimeConfig(root proxy.RootConfig) {
	rtMu.Lock()
	rtKeyHashes = map[string]struct{}{}
	for _, k := range root.APIKeys {
		if k.Hash != "" {
			rtKeyHashes[k.Hash] = struct{}{}
		}
	}
	rtDefDetectors = root.DefaultDetectors
	rtDefWhitelist = root.DefaultWhitelist
	rtCORSOrigins = root.CORSOrigins
	rtMu.Unlock()

	// Update proxy guards in-place — no restart required.
	for _, p := range root.Proxies {
		proxy.UpdateGuardConfig(p.Port, p.PrivacyGuard)
	}
}

// corsMiddleware sets Access-Control-Allow-Origin when the request Origin matches
// a configured origin. Handles OPTIONS preflight requests automatically.
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rtMu.RLock()
		origins := rtCORSOrigins
		rtMu.RUnlock()

		origin := r.Header.Get("Origin")
		if origin != "" && len(origins) > 0 {
			allowed := false
			for _, o := range origins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Run starts the API server on the given port. Blocks until error.
func Run(port int, cfgPath string) {
	cfgFile = cfgPath
	if root, err := proxy.LoadConfigs(cfgPath); err == nil {
		applyRuntimeConfig(root)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	// REST API (CORS + optional auth)
	mux.HandleFunc("GET /health", corsMiddleware(handleHealth))
	mux.HandleFunc("GET /metrics", corsMiddleware(handleMetrics))
	mux.HandleFunc("OPTIONS /anonymize", corsMiddleware(handleHealth)) // preflight
	mux.HandleFunc("OPTIONS /scan", corsMiddleware(handleHealth))      // preflight
	mux.HandleFunc("POST /anonymize", corsMiddleware(rateLimit(apiKeyAuth(handleAnonymize))))
	mux.HandleFunc("POST /scan", corsMiddleware(rateLimit(apiKeyAuth(handleScan))))
	// Web UI
	mux.HandleFunc("GET /login", handleLoginPage)
	mux.HandleFunc("POST /login", handleLoginSubmit)
	mux.HandleFunc("GET /logout", handleLogout)
	mux.HandleFunc("GET /change-password", handleChangePasswordPage)
	mux.HandleFunc("POST /change-password", handleChangePasswordSubmit)
	mux.HandleFunc("GET /", handleUI)
	mux.HandleFunc("POST /ui/config", handleSaveConfig)
	mux.HandleFunc("POST /ui/proxy/add", handleAddProxy)
	mux.HandleFunc("POST /ui/proxy/delete", handleDeleteProxy)
	mux.HandleFunc("GET /test", handleTestPage)
	mux.HandleFunc("POST /ui/scan", handleUIScan)
	mux.HandleFunc("GET /logs", handleLogsPage)
	mux.HandleFunc("GET /ui/logs/tail", handleLogsTail)
	mux.HandleFunc("POST /ui/apikey/add", handleAddAPIKey)
	mux.HandleFunc("POST /ui/apikey/delete", handleDeleteAPIKey)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	slog.Info("privacy-guard API listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("API server error", "err", err)
	}
}

// apiKeyAuth wraps a handler with optional API-key authentication.
func apiKeyAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rtMu.RLock()
		n := len(rtKeyHashes)
		rtMu.RUnlock()
		if n == 0 {
			next(w, r)
			return
		}
		key := r.Header.Get("X-Api-Key")
		if key == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if key == "" {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		kh := hashKey(key)
		rtMu.RLock()
		_, ok := rtKeyHashes[kh]
		rtMu.RUnlock()
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
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
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(proxy.MetricsText()))
}

func handleAnonymize(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	dets := req.Detectors
	if len(dets) == 0 {
		rtMu.RLock()
		dets = rtDefDetectors
		rtMu.RUnlock()
	}
	wl := mergedWhitelist(req.Whitelist)
	anonymised, _ := detector.NewScanner(dets).ScanWithWhitelist(req.Text, wl)
	writeJSON(w, anonymizeResponse{AnonymisedText: anonymised})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	dets := req.Detectors
	if len(dets) == 0 {
		rtMu.RLock()
		dets = rtDefDetectors
		rtMu.RUnlock()
	}
	wl := mergedWhitelist(req.Whitelist)
	anonymised, findings := detector.NewScanner(dets).ScanWithWhitelist(req.Text, wl)

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

func mergedWhitelist(req []string) []string {
	rtMu.RLock()
	base := append([]string(nil), rtDefWhitelist...)
	rtMu.RUnlock()
	set := map[string]struct{}{}
	var out []string
	for _, v := range append(base, req...) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := set[key]; ok {
			continue
		}
		set[key] = struct{}{}
		out = append(out, v)
	}
	return out
}

func rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !allowRequest(rateKey(r), time.Now().Unix()/60) {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func allowRequest(key string, minute int64) bool {
	rtRateMu.Lock()
	defer rtRateMu.Unlock()
	win, ok := rtRateState[key]
	if !ok || win.Minute != minute {
		rtRateState[key] = rateWindow{Minute: minute, Count: 1}
		return true
	}
	if win.Count >= apiRateLimitPerMinute {
		return false
	}
	win.Count++
	rtRateState[key] = win
	return true
}

func rateKey(r *http.Request) string {
	key := r.Header.Get("X-Api-Key")
	if key == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			key = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if key != "" {
		return "k:" + hashKey(key)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("failed to encode response", "err", err)
	}
}
