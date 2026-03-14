# privacy-guard-proxy

A local proxy that sits between [Claude Code](https://claude.ai/code) and the Anthropic API and automatically masks PII in every request before it leaves your machine.

Names, email addresses, IBANs, API keys, and other sensitive data are replaced with placeholders like `[EMAIL_1]` or `[IBAN_1]` — Claude never sees the real values.

No external service required — all detection runs in-process.

## How it works

```
Claude Code  →  privacy-guard-proxy (PII masking, built-in)  →  Anthropic API
```

Every outgoing request is intercepted. User messages, tool results, and file contents are scanned and anonymised before being forwarded upstream. Responses are passed through unchanged.

## Quick start

```bash
# 1. Build
go build -o privacy-guard-proxy .

# 2. Start the proxy
./privacy-guard-proxy

# 3. Point Claude Code at the proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:9880
claude
```

## Optional: built-in HTTP API

The proxy can also expose a privacy-guard-compatible HTTP API for direct use from other tools or scripts:

```bash
./privacy-guard-proxy --api-port 8090
# or
PRIVACY_GUARD_API_PORT=8090 ./privacy-guard-proxy
```

```bash
# Anonymise text
curl http://localhost:8090/anonymize \
  -d '{"text": "Meine IBAN: DE89370400440532013000"}' | jq

# Full scan with findings + mapping
curl http://localhost:8090/scan \
  -d '{"text": "foo@example.com, +49 171 1234567"}' | jq

# Health check
curl http://localhost:8090/health
```

Selective detectors per request:

```bash
curl http://localhost:8090/scan \
  -d '{"text": "...", "detectors": ["EMAIL", "IBAN", "SECRET"]}' | jq
```

## Configuration

`config.json` — multiple proxy instances are supported:

```json
[
  {
    "type": "claude-code",
    "port": 9880,
    "upstream": "https://api.anthropic.com",
    "privacy_guard": {
      "detectors": ["SECRET"],
      "whitelist": ["claude", "anthropic"]
    }
  }
]
```

| Field | Description |
|---|---|
| `type` | Request format — use `claude-code` for Claude Code |
| `port` | Local port the proxy listens on |
| `upstream` | Anthropic API base URL |
| `privacy_guard.detectors` | PII types to detect — empty means all |
| `privacy_guard.whitelist` | Terms to never mask |

## Detected PII types

| Type | Examples | Validation |
|---|---|---|
| `EMAIL` | `foo@example.com` | Regex |
| `PHONE` | `+49 171 1234567`, `030 12345678` | DACH formats, ≥ 9 digits |
| `IBAN` | `DE89 3704 0044 0532 0130 00` | MOD-97 checksum, 94 countries |
| `CREDIT_CARD` | `4111-1111-1111-1111` | Luhn algorithm |
| `TAX_ID` | `86 095 742 719` | § 139b AO mod-11 |
| `SOCIAL_SECURITY` | `65 180675 B 003` | German SVN format |
| `KVNR` | `A123456789` | § 290 SGB V modified Luhn |
| `VAT_ID` | `DE 123 456 789` | German USt-IdNr |
| `PERSONAL_ID` | `C22990047` | German Personalausweis / Reisepass |
| `LICENSE_PLATE` | `M-AB 1234`, `B-XY 999H` | German Kfz-Kennzeichen |
| `DRIVER_LICENSE` | `B123456AB` | Context-validated Führerscheinnummer |
| `ADDRESS` | `Musterstraße 12, 80331 München` | DACH street + PLZ + city |
| `URL_SECRET` | `?token=abc123` | URL query parameter secrets |
| `SECRET` | AWS keys, GitHub PATs, JWTs, … | ~100 rules (cloud, AI, DB, …) |

## What gets masked

| Content | Masked |
|---|---|
| User messages | ✅ |
| File contents (via tool results) | ✅ |
| Tool inputs (e.g. Write, Edit) | ✅ |
| System prompt | ✗ (contains model instructions, not user data) |
| Assistant responses | ✗ |

## Project structure

```
internal/
├── detector/    # PII detection (Scanner, 14 detector types)
├── proxy/       # HTTP reverse proxy + masking logic
└── api/         # Optional HTTP API server
main.go          # Entry point
```
