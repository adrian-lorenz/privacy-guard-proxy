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

	root, err := proxy.LoadConfigs("config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load config.json: %v\n", err)
		os.Exit(1)
	}

	// api_port from config is used when not overridden by flag/env
	if *apiPort == 0 && root.APIPort > 0 {
		*apiPort = root.APIPort
	}

	const sep = "────────────────────────────────────────────────"
	fmt.Println()
	fmt.Println("  privacy-guard-proxy")
	fmt.Println(" ", sep)
	fmt.Println()

	var wg sync.WaitGroup

	for _, cfg := range root.Proxies {
		upstreamBase := strings.TrimRight(cfg.Upstream, "/")
		detectors := "all"
		if len(cfg.PrivacyGuard.Detectors) > 0 {
			detectors = strings.Join(cfg.PrivacyGuard.Detectors, ", ")
		}
		whitelist := "—"
		if len(cfg.PrivacyGuard.Whitelist) > 0 {
			whitelist = strings.Join(cfg.PrivacyGuard.Whitelist, ", ")
		}
		fmt.Printf("  proxy    :%d  %s  →  %s\n", cfg.Port, cfg.Type, upstreamBase)
		fmt.Printf("           detectors : %s\n", detectors)
		fmt.Printf("           whitelist : %s\n", whitelist)
		fmt.Println()

		wg.Add(1)
		go func(cfg proxy.Config) {
			defer wg.Done()
			proxy.RunProxy(cfg)
		}(cfg)
	}

	if *apiPort > 0 {
		fmt.Printf("  api      http://localhost:%d\n", *apiPort)
		fmt.Printf("  ui       http://localhost:%d\n", *apiPort)
		fmt.Println()
		wg.Add(1)
		go func() {
			defer wg.Done()
			api.Run(*apiPort, "config.json")
		}()
	}

	fmt.Println(" ", sep)
	for _, cfg := range root.Proxies {
		fmt.Printf("  export ANTHROPIC_BASE_URL=http://127.0.0.1:%d\n", cfg.Port)
	}
	fmt.Println()

	wg.Wait()
}
