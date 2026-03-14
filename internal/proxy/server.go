package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RunProxy starts the HTTP reverse proxy for the given Config. Blocks until error.
func RunProxy(cfg Config) {
	guard := NewGuard(cfg.PrivacyGuard)
	upstreamBase := strings.TrimRight(cfg.Upstream, "/")

	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg, upstreamBase, guard, client)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("[:%d] server error: %v\n", cfg.Port, err)
	}
}

func handleRequest(
	w http.ResponseWriter,
	r *http.Request,
	cfg Config,
	upstream string,
	guard *Guard,
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

	maskedBody, summary := guard.Apply(bodyBytes, cfg.Type)

	fmt.Printf("[:%d] → %s %s", port, r.Method, path)
	if summary.PIIFound > 0 {
		fmt.Printf("  (%d PII masked: %s)", summary.PIIFound, strings.Join(summary.Placeholders, ", "))
	}
	fmt.Println()

	upstreamReq, err := http.NewRequest(r.Method, upstream+path, strings.NewReader(string(maskedBody)))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	skipReq := map[string]bool{"host": true, "connection": true, "transfer-encoding": true, "content-length": true}
	for k, vals := range r.Header {
		if skipReq[strings.ToLower(k)] {
			continue
		}
		for _, v := range vals {
			upstreamReq.Header.Add(k, v)
		}
	}

	resp, err := client.Do(upstreamReq)
	if err != nil {
		fmt.Printf("[:%d] upstream error: %v\n", port, err)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("[:%d] ← %d  (%d bytes)\n", port, resp.StatusCode, len(respBody))

	skipResp := map[string]bool{"connection": true, "transfer-encoding": true}
	for k, vals := range resp.Header {
		if skipResp[strings.ToLower(k)] {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}
