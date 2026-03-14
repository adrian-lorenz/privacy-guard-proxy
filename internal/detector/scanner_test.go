package detector

import (
	"strings"
	"testing"
)

func TestScannerSingleIBAN(t *testing.T) {
	s := NewScanner(nil)
	anon, findings := s.Scan("Bitte überweise an DE89 3704 0044 0532 0130 00")
	if !strings.Contains(anon, "[IBAN_1]") {
		t.Errorf("expected [IBAN_1] in %q", anon)
	}
	if strings.Contains(anon, "DE89 3704 0044 0532 0130 00") {
		t.Errorf("IBAN should be redacted in %q", anon)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
}

func TestScannerEmail(t *testing.T) {
	s := NewScanner(nil)
	anon, findings := s.Scan("Schreib an: kontakt@example.de")
	if !strings.Contains(anon, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] in %q", anon)
	}
	if strings.Contains(anon, "kontakt@example.de") {
		t.Errorf("email should be redacted in %q", anon)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
}

func TestScannerPhone(t *testing.T) {
	s := NewScanner(nil)
	anon, _ := s.Scan("Ruf mich an: +49 171 1234567")
	if !strings.Contains(anon, "[PHONE_1]") {
		t.Errorf("expected [PHONE_1] in %q", anon)
	}
}

func TestScannerAddress(t *testing.T) {
	s := NewScanner(nil)
	anon, _ := s.Scan("Ich wohne in der Hauptstraße 5, 10115 Berlin.")
	if !strings.Contains(anon, "[ADDRESS_1]") {
		t.Errorf("expected [ADDRESS_1] in %q", anon)
	}
}

func TestScannerNoMatch(t *testing.T) {
	s := NewScanner(nil)
	text := "Kein PII hier."
	anon, findings := s.Scan(text)
	if anon != text {
		t.Errorf("text should be unchanged, got %q", anon)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestScannerDeduplication(t *testing.T) {
	s := NewScanner(nil)
	// Same email twice → same placeholder both times
	anon, findings := s.Scan("info@example.de und info@example.de")
	count := strings.Count(anon, "[EMAIL_1]")
	if count != 2 {
		t.Errorf("expected [EMAIL_1] twice, got %d times in %q", count, anon)
	}
	// Only one unique placeholder should be assigned
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Placeholder] = true
	}
	if len(seen) != 1 {
		t.Errorf("expected 1 unique placeholder, got %d: %v", len(seen), findings)
	}
}

func TestScannerFindingsSortedByStart(t *testing.T) {
	s := NewScanner(nil)
	_, findings := s.Scan("kontakt@example.de und DE89 3704 0044 0532 0130 00 und +49 171 1234567")
	for i := 1; i < len(findings); i++ {
		if findings[i].Start < findings[i-1].Start {
			t.Errorf("findings not sorted: [%d].Start=%d < [%d].Start=%d",
				i, findings[i].Start, i-1, findings[i-1].Start)
		}
	}
}

func TestScannerRestoreRoundtrip(t *testing.T) {
	s := NewScanner(nil)
	text := "Antwort an info@musterfirma.de bitte bis Freitag."
	anon, findings := s.Scan(text)
	// Build reverse mapping
	restore := map[string]string{}
	for _, f := range findings {
		restore[f.Placeholder] = f.Text
	}
	restored := anon
	for ph, orig := range restore {
		restored = strings.ReplaceAll(restored, ph, orig)
	}
	if restored != text {
		t.Errorf("roundtrip failed:\n  got  %q\n  want %q", restored, text)
	}
}

func TestScannerSelectiveDetectors(t *testing.T) {
	// Only enable IBAN — phone should not be redacted
	s := NewScanner([]string{"IBAN"})
	text := "IBAN: DE89 3704 0044 0532 0130 00, Tel: +49 171 1234567"
	anon, findings := s.Scan(text)
	if !strings.Contains(anon, "[IBAN_1]") {
		t.Errorf("expected [IBAN_1] in %q", anon)
	}
	if !strings.Contains(anon, "+49 171 1234567") {
		t.Errorf("phone should NOT be redacted when only IBAN enabled, got %q", anon)
	}
	for _, f := range findings {
		if f.Type != PiiIBAN {
			t.Errorf("expected only IBAN findings, got %v", f.Type)
		}
	}
}

func TestScannerPlaceholderFormat(t *testing.T) {
	s := NewScanner(nil)
	_, findings := s.Scan("kontakt@example.de")
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	f := findings[0]
	if f.Placeholder != "[EMAIL_1]" {
		t.Errorf("placeholder = %q, want [EMAIL_1]", f.Placeholder)
	}
	if f.Type != PiiEmail {
		t.Errorf("type = %v, want EMAIL", f.Type)
	}
}

func TestScannerMultipleTypes(t *testing.T) {
	s := NewScanner(nil)
	text := "Email: test@example.com, IBAN: DE89 3704 0044 0532 0130 00"
	anon, findings := s.Scan(text)
	if !strings.Contains(anon, "[EMAIL_1]") {
		t.Errorf("missing EMAIL placeholder in %q", anon)
	}
	if !strings.Contains(anon, "[IBAN_1]") {
		t.Errorf("missing IBAN placeholder in %q", anon)
	}
	types := map[PiiType]bool{}
	for _, f := range findings {
		types[f.Type] = true
	}
	if !types[PiiEmail] {
		t.Error("EMAIL finding missing")
	}
	if !types[PiiIBAN] {
		t.Error("IBAN finding missing")
	}
}

func TestScannerSecretDetected(t *testing.T) {
	s := NewScanner(nil)
	anon, findings := s.Scan("key=AKIAIOSFODNN7EXAMPLE")
	if !strings.Contains(anon, "[SECRET_1]") {
		t.Errorf("expected [SECRET_1] in %q", anon)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Type != PiiSecret {
		t.Errorf("type = %v, want SECRET", findings[0].Type)
	}
}

func TestScannerCountersPerType(t *testing.T) {
	s := NewScanner(nil)
	// Two different emails → EMAIL_1 and EMAIL_2
	anon, _ := s.Scan("a@example.com und b@example.com")
	if !strings.Contains(anon, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] in %q", anon)
	}
	if !strings.Contains(anon, "[EMAIL_2]") {
		t.Errorf("expected [EMAIL_2] in %q", anon)
	}
}
