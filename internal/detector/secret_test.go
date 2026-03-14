package detector

import "testing"

func TestDetectSecrets(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantN      int
		wantRuleID string // rule that must fire (empty = any)
		wantText   string // expected secret value (empty = any)
	}{
		{
			"aws access key",
			"key=AKIAIOSFODNN7EXAMPLE",
			1, "aws-access-key", "AKIAIOSFODNN7EXAMPLE",
		},
		{
			"github pat",
			"token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
			1, "github-pat", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
		},
		{
			"gitlab pat",
			"glpat-ABCDEFGHIJKLMNOPQRST",
			1, "gitlab-pat", "glpat-ABCDEFGHIJKLMNOPQRST",
		},
		{
			"anthropic api key",
			"sk-ant-api03-" + repeatStr("A", 32),
			1, "anthropic-api-key", "",
		},
		{
			"openai sk-proj",
			"sk-proj-" + repeatStr("A", 50),
			1, "openai-api-key-new", "",
		},
		{
			"huggingface token",
			"hf_" + repeatStr("a", 32),
			1, "huggingface-token", "",
		},
		{
			"groq api key",
			"gsk_" + repeatStr("A", 52),
			1, "groq-api-key", "",
		},
		{
			"postgres url",
			"postgres://user:password@localhost:5432/mydb",
			1, "db-postgres-url", "",
		},
		{
			"mongodb url",
			"mongodb://user:pass@cluster.mongodb.net/db",
			1, "db-mongodb-url", "",
		},
		{
			"pem private key header",
			"-----BEGIN RSA PRIVATE KEY-----",
			1, "private-key-header", "",
		},
		{
			"jwt token",
			"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			1, "jwt-token", "",
		},
		{
			"generic secret assignment",
			`password = "mySecretPassword123"`,
			1, "generic-secret", "mySecretPassword123",
		},
		{
			"python inline openai key",
			`client = OpenAI(api_key="sk-testkey1234567890abcdefghij")`,
			1, "python-openai-client-inline-key", "",
		},
		{
			"gcp service account",
			`{"type": "service_account", "project_id": "my-project"}`,
			1, "gcp-service-account", "",
		},
		{
			"only secret value redacted not key name",
			"ANTHROPIC_API_KEY=sk-ant-api03-" + repeatStr("B", 32),
			1, "anthropic-api-key-env", "",
		},
		{
			"no match plain text",
			"Hallo, das ist ein normaler Text ohne Secrets.",
			0, "", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSecrets(tt.input)
			if len(got) < tt.wantN {
				t.Fatalf("got %d findings, want at least %d — %v", len(got), tt.wantN, got)
			}
			if tt.wantN == 0 {
				return
			}
			if tt.wantRuleID != "" {
				found := false
				for _, f := range got {
					if f.RuleID == tt.wantRuleID {
						found = true
						if tt.wantText != "" && f.Text != tt.wantText {
							t.Errorf("rule %q: text = %q, want %q", tt.wantRuleID, f.Text, tt.wantText)
						}
						break
					}
				}
				if !found {
					t.Errorf("rule %q not fired — got rules: %v", tt.wantRuleID, ruleIDs(got))
				}
			}
			for _, f := range got {
				if f.Type != PiiSecret {
					t.Errorf("type = %v, want SECRET", f.Type)
				}
				if f.Confidence <= 0 {
					t.Errorf("confidence = %v, want > 0", f.Confidence)
				}
			}
		})
	}
}

func ruleIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}
