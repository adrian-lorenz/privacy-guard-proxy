package proxy

import (
	"encoding/json"
	"os"
)

// Config is one proxy instance loaded from config.json.
type Config struct {
	Type         string      `json:"type"` // e.g. "claude-code"
	Port         int         `json:"port"`
	Upstream     string      `json:"upstream"`
	PrivacyGuard GuardConfig `json:"privacy_guard"`
}

// GuardConfig holds per-instance detector configuration.
// URL and APIKey are legacy fields kept for JSON backward-compatibility.
type GuardConfig struct {
	URL       string   `json:"url"`
	APIKey    *string  `json:"api_key"`
	Detectors []string `json:"detectors"`
	Whitelist []string `json:"whitelist"`
}

// LoadConfigs reads config.json. Falls back to DefaultConfig if the file is absent.
func LoadConfigs(path string) ([]Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []Config{DefaultConfig()}, nil
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

// DefaultConfig returns a sensible single-proxy config.
func DefaultConfig() Config {
	return Config{
		Port:     8080,
		Upstream: "https://api.anthropic.com",
		PrivacyGuard: GuardConfig{
			Detectors: []string{},
			Whitelist: []string{},
		},
	}
}
