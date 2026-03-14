package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/adrian-lorenz/privacy-guard-proxy/internal/api"
	"github.com/adrian-lorenz/privacy-guard-proxy/internal/proxy"
)

func main() {
	apiPort := flag.Int("api-port", 0, "port for the built-in privacy-guard HTTP API (0 = disabled)")
	flag.Parse()

	if *apiPort == 0 {
		fmt.Sscan(os.Getenv("PRIVACY_GUARD_API_PORT"), apiPort)
	}

	cfgs, err := proxy.LoadConfigs("config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load config.json: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup

	if *apiPort > 0 {
		fmt.Printf("[API]   privacy-guard API → 0.0.0.0:%d\n", *apiPort)
		wg.Add(1)
		go func() {
			defer wg.Done()
			api.Run(*apiPort)
		}()
	}

	for _, cfg := range cfgs {
		upstreamBase := strings.TrimRight(cfg.Upstream, "/")
		detectors := "all"
		if len(cfg.PrivacyGuard.Detectors) > 0 {
			detectors = strings.Join(cfg.PrivacyGuard.Detectors, ",")
		}
		fmt.Printf("[:%d]  type → %s   upstream → %s   detectors → %s\n",
			cfg.Port, cfg.Type, upstreamBase, detectors)

		wg.Add(1)
		go func(cfg proxy.Config) {
			defer wg.Done()
			proxy.RunProxy(cfg)
		}(cfg)
	}

	fmt.Println()
	for _, cfg := range cfgs {
		fmt.Printf("  export ANTHROPIC_BASE_URL=http://127.0.0.1:%d\n", cfg.Port)
	}
	if *apiPort > 0 {
		fmt.Printf("\n  API: curl -s http://localhost:%d/scan -d '{\"text\":\"foo@bar.com\"}' | jq\n", *apiPort)
	}
	fmt.Println()

	wg.Wait()
}
