package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config is one proxy instance loaded from config.json.
type Config struct {
	Type         string             `json:"type"` // e.g. "claude-code"
	Port         int                `json:"port"`
	Upstream     string             `json:"upstream"`
	PrivacyGuard PrivacyGuardConfig `json:"privacy_guard"`
}

func loadConfigs(path string) ([]Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []Config{defaultConfig()}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfgs []Config
	if err := json.Unmarshal(data, &cfgs); err != nil {
		return nil, err
	}
	return cfgs, nil
}

func defaultConfig() Config {
	pgURL := os.Getenv("PRIVACY_GUARD_URL")
	if pgURL == "" {
		pgURL = "http://localhost:8000"
	}
	var apiKey *string
	if k := os.Getenv("PRIVACY_GUARD_API_KEY"); k != "" {
		apiKey = &k
	}
	return Config{
		Port:     8080,
		Upstream: "https://api.anthropic.com",
		PrivacyGuard: PrivacyGuardConfig{
			URL:       pgURL,
			APIKey:    apiKey,
			Detectors: []string{},
			Whitelist: []string{},
		},
	}
}

func main() {
	cfgs, err := loadConfigs("config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load config.json: %v\n", err)
		os.Exit(1)
	}

	hcClient := &http.Client{Timeout: 3 * time.Second}

	var wg sync.WaitGroup
	for _, cfg := range cfgs {
		pgStatus := healthCheck(hcClient, cfg.PrivacyGuard.URL)
		upstreamBase := strings.TrimRight(cfg.Upstream, "/")

		fmt.Printf("[:%d]  type → %s   upstream → %s   privacy-guard → %s [%s]\n",
			cfg.Port, cfg.Type, upstreamBase, cfg.PrivacyGuard.URL, pgStatus)

		wg.Add(1)
		go func(cfg Config) {
			defer wg.Done()
			runProxy(cfg)
		}(cfg)
	}

	fmt.Println()
	for _, cfg := range cfgs {
		fmt.Printf("  export ANTHROPIC_BASE_URL=http://127.0.0.1:%d\n", cfg.Port)
	}
	fmt.Println()

	wg.Wait()
}

func runProxy(cfg Config) {
	pg := NewPrivacyGuard(cfg.PrivacyGuard)
	upstreamBase := strings.TrimRight(cfg.Upstream, "/")

	proxyClient := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg, upstreamBase, pg, proxyClient)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "[:%d] server error: %v\n", cfg.Port, err)
	}
}

func handleRequest(
	w http.ResponseWriter,
	r *http.Request,
	cfg Config,
	upstream string,
	pg *PrivacyGuard,
	client *http.Client,
) {
	port := cfg.Port
	path := r.URL.RequestURI()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	maskedBody, summary := pg.Apply(bodyBytes, cfg.Type)

	fmt.Printf("[:%d] → %s %s", port, r.Method, path)
	if summary.PIIFound > 0 {
		fmt.Printf("  (%d PII masked: %s)", summary.PIIFound, strings.Join(summary.Placeholders, ", "))
	}
	fmt.Println()

	upstreamURL := upstream + path
	upstreamReq, err := http.NewRequest(r.Method, upstreamURL, strings.NewReader(string(maskedBody)))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	skip := map[string]bool{
		"host": true, "connection": true, "transfer-encoding": true, "content-length": true,
	}
	for k, vals := range r.Header {
		if skip[strings.ToLower(k)] {
			continue
		}
		for _, v := range vals {
			upstreamReq.Header.Add(k, v)
		}
	}

	upstreamResp, err := client.Do(upstreamReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[:%d] upstream error: %v\n", port, err)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer upstreamResp.Body.Close()

	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		respBody = []byte{}
	}

	fmt.Printf("[:%d] ← %d  (%d bytes)\n", port, upstreamResp.StatusCode, len(respBody))

	skipResp := map[string]bool{"connection": true, "transfer-encoding": true}
	for k, vals := range upstreamResp.Header {
		if skipResp[strings.ToLower(k)] {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(upstreamResp.StatusCode)
	w.Write(respBody)
}

func healthCheck(client *http.Client, pgURL string) string {
	url := strings.TrimRight(pgURL, "/") + "/health"
	resp, err := client.Get(url)
	if err != nil {
		return "unreachable"
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "ok"
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode)
}
