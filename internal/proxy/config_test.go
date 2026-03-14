package proxy

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLoadConfigsMissingFile(t *testing.T) {
	root, err := LoadConfigs("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if len(root.Proxies) == 0 {
		t.Error("expected default proxy when file is absent")
	}
}

func TestLoadConfigsValid(t *testing.T) {
	cfg := RootConfig{
		APIPort: 9090,
		Proxies: []Config{
			{
				Type:     "claude-code",
				Port:     9880,
				Upstream: "https://api.anthropic.com",
				PrivacyGuard: GuardConfig{
					Detectors: []string{"EMAIL", "PHONE"},
					Whitelist: []string{"claude"},
				},
			},
		},
	}
	data, _ := json.Marshal(cfg)
	f, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	got, err := LoadConfigs(f.Name())
	if err != nil {
		t.Fatalf("LoadConfigs error: %v", err)
	}
	if got.APIPort != 9090 {
		t.Errorf("APIPort = %d, want 9090", got.APIPort)
	}
	if len(got.Proxies) != 1 {
		t.Fatalf("len(Proxies) = %d, want 1", len(got.Proxies))
	}
	if got.Proxies[0].Port != 9880 {
		t.Errorf("Port = %d, want 9880", got.Proxies[0].Port)
	}
	if len(got.Proxies[0].PrivacyGuard.Detectors) != 2 {
		t.Errorf("Detectors = %v, want [EMAIL PHONE]", got.Proxies[0].PrivacyGuard.Detectors)
	}
}

func TestLoadConfigsEmptyProxiesGetsDefault(t *testing.T) {
	raw := `{"api_port": 8080, "proxies": []}`
	f, _ := os.CreateTemp("", "config-*.json")
	defer os.Remove(f.Name())
	f.WriteString(raw)
	f.Close()

	got, err := LoadConfigs(f.Name())
	if err != nil {
		t.Fatalf("LoadConfigs error: %v", err)
	}
	if len(got.Proxies) != 1 {
		t.Errorf("expected default proxy injected, got %d proxies", len(got.Proxies))
	}
}

func TestLoadConfigsInvalidJSON(t *testing.T) {
	f, _ := os.CreateTemp("", "config-*.json")
	defer os.Remove(f.Name())
	f.WriteString(`{not valid json`)
	f.Close()

	_, err := LoadConfigs(f.Name())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadConfigsLegacyArrayFormat(t *testing.T) {
	raw := `[
  {"type":"claude-code","port":9880,"upstream":"https://api.anthropic.com","privacy_guard":{"detectors":["EMAIL"],"whitelist":[]}}
]`
	f, _ := os.CreateTemp("", "config-legacy-*.json")
	defer os.Remove(f.Name())
	_, _ = f.WriteString(raw)
	_ = f.Close()

	got, err := LoadConfigs(f.Name())
	if err != nil {
		t.Fatalf("LoadConfigs legacy format error: %v", err)
	}
	if len(got.Proxies) != 1 {
		t.Fatalf("expected 1 proxy from legacy config, got %d", len(got.Proxies))
	}
	if got.Proxies[0].Port != 9880 {
		t.Fatalf("legacy proxy port = %d, want 9880", got.Proxies[0].Port)
	}
}
