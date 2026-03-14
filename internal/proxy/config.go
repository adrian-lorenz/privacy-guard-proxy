package proxy

import (
	"encoding/json"
	"os"
)

// RootConfig is the top-level structure of config.json.
type RootConfig struct {
	APIPort          int      `json:"api_port"`
	APIKeys          []APIKey `json:"api_keys"`
	DefaultDetectors []string `json:"default_detectors"`
	DefaultWhitelist []string `json:"default_whitelist"`
	CORSOrigins      []string `json:"cors_origins"`     // allowed origins for API CORS (empty = CORS off)
	UIPasswordHash   string   `json:"ui_password_hash"` // hex(sha256(password)); empty = default admin/admin, change required
	Proxies          []Config `json:"proxies"`
}

// APIKey holds the metadata and SHA-256 hash of a single API key.
// The original key value is never stored.
type APIKey struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Hash    string `json:"hash"`    // hex(sha256(original_key))
	Hint    string `json:"hint"`    // first 12 chars + "****"
	Created string `json:"created"` // YYYY-MM-DD
}

// Config is one proxy instance.
type Config struct {
	Type         string      `json:"type"`
	Port         int         `json:"port"`
	Upstream     string      `json:"upstream"`
	PrivacyGuard GuardConfig `json:"privacy_guard"`
}

// GuardConfig holds per-instance detector configuration.
type GuardConfig struct {
	URL       string   `json:"url"`
	APIKey    *string  `json:"api_key"`
	Detectors []string `json:"detectors"`
	Whitelist []string `json:"whitelist"`
	DryRun    bool     `json:"dry_run,omitempty"`
}

// LoadConfigs reads config.json. Falls back to DefaultRootConfig if the file is absent.
func LoadConfigs(path string) (RootConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return DefaultRootConfig(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return RootConfig{}, err
	}
	var root RootConfig
	if err := json.Unmarshal(data, &root); err != nil {
		// Backward compatibility: legacy top-level []Config format.
		var legacy []Config
		if err2 := json.Unmarshal(data, &legacy); err2 != nil {
			return RootConfig{}, err
		}
		root = RootConfig{Proxies: legacy}
	}
	if len(root.Proxies) == 0 {
		root.Proxies = []Config{DefaultConfig()}
	}
	return root, nil
}

// DefaultRootConfig returns a sensible default configuration.
func DefaultRootConfig() RootConfig {
	return RootConfig{
		Proxies: []Config{DefaultConfig()},
	}
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
