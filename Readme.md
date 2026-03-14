# privacy-guard-proxy

`privacy-guard-proxy` is a local reverse proxy for [Claude Code](https://claude.ai/code) that masks sensitive data before it leaves your machine.

Email addresses, names, IBANs, API keys, IDs, addresses, and other secrets are replaced with placeholders like `[EMAIL_1]` or `[IBAN_1]` on the way to the Anthropic API. Detection runs fully in-process. No external redaction service is involved.

![App screenshot](img.png)

## Why use it?

- Keep PII and secrets out of model requests by default
- Run locally with no extra SaaS dependency
- Use it as a drop-in proxy for Claude Code
- Inspect detections, logs, and config in a built-in Web UI
- Expose the same detector engine through a REST API

## How it works

```text
Claude Code -> privacy-guard-proxy -> Anthropic API
              | masks PII + secrets |
```

Before a request is forwarded upstream, the proxy scans user messages, tool payloads, and file contents for sensitive data. Matching values are replaced with stable placeholders. Upstream responses are passed through unchanged.

## Quick start

### Local binary

```bash
cp config.example.json config.json
go build -o privacy-guard-proxy .
./privacy-guard-proxy

export ANTHROPIC_BASE_URL=http://127.0.0.1:9880
claude
```

By default:

- Proxy: `http://127.0.0.1:9880`
- Web UI + REST API: `http://127.0.0.1:9881`

### Docker Compose

```bash
cp config.example.json config.json
docker compose up -d
```

The compose setup exposes the same two ports and mounts `config.json` plus `./logs`.

## What gets masked?

| Content | Masked |
|---|---|
| User messages | Yes |
| File contents returned by tools | Yes |
| Tool inputs such as write/edit payloads | Yes |
| System prompt | No |
| Assistant responses | No |

## Web UI

If `api_port` is enabled, the browser UI is available at `http://localhost:9881`.

![Web UI](img_1.png)

First login:

- Username: `admin`
- Password: `admin`

You are forced to change the password on first login.

The UI lets you:

- Manage one or more proxy instances
- Choose detectors and whitelists per proxy
- Enable `dry_run` mode to log findings without modifying requests
- Manage REST API keys without storing plaintext secrets
- Configure default detectors, default whitelist, and CORS
- Inspect live proxy logs
- Test detector behavior interactively

## REST API

The built-in API exposes the same detector engine used by the proxy.

```bash
# Anonymize text
curl http://localhost:9881/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text":"Meine IBAN: DE89370400440532013000"}' | jq

# Full scan with findings and placeholder mapping
curl http://localhost:9881/scan \
  -H "Content-Type: application/json" \
  -d '{"text":"foo@example.com, +49 171 1234567"}' | jq

# Use selected detectors for this request only
curl http://localhost:9881/scan \
  -H "Content-Type: application/json" \
  -d '{"text":"...", "detectors":["EMAIL","IBAN","SECRET"]}' | jq

# Health and metrics
curl http://localhost:9881/health
curl http://localhost:9881/metrics
```

Authentication is optional. If no API keys are configured, requests are accepted without auth.

```bash
curl http://localhost:9881/scan \
  -H "X-Api-Key: pgk_..." \
  -H "Content-Type: application/json" \
  -d '{"text":"..."}'
```

Current limit:

- `/scan` and `/anonymize`: `120` requests per minute
- Limit is applied per API key, or per client IP when auth is disabled

## Configuration

Start from [`config.example.json`](config.example.json) and adjust as needed:

```json
{
  "api_port": 9881,
  "api_keys": [],
  "default_detectors": [],
  "default_whitelist": [],
  "cors_origins": [],
  "ui_password_hash": "",
  "proxies": [
    {
      "type": "claude-code",
      "port": 9880,
      "upstream": "https://api.anthropic.com",
      "privacy_guard": {
        "url": "",
        "api_key": null,
        "detectors": [],
        "whitelist": [],
        "dry_run": false
      }
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `api_port` | Port for Web UI and REST API. `0` disables both. |
| `api_keys` | Stored API key metadata and hashes for protecting `/scan` and `/anonymize`. |
| `default_detectors` | Fallback detector list for API requests that do not specify `detectors`. Empty means all detectors. |
| `default_whitelist` | Global terms that should never be masked by the REST API. |
| `cors_origins` | Allowed browser origins for the REST API. Empty means CORS is off. |
| `ui_password_hash` | SHA-256 hash of the UI password. Empty means initial `admin/admin`. |
| `proxies[].type` | Request format. Use `claude-code` for Claude Code traffic. |
| `proxies[].port` | Local listening port of this proxy instance. |
| `proxies[].upstream` | Upstream Anthropic base URL. |
| `proxies[].privacy_guard.url` | Reserved config field for compatibility. |
| `proxies[].privacy_guard.api_key` | Optional per-proxy upstream API key override. |
| `proxies[].privacy_guard.detectors` | Enabled detector types. Empty means all detectors. |
| `proxies[].privacy_guard.whitelist` | Terms that should never be replaced for this proxy. |
| `proxies[].privacy_guard.dry_run` | Detect and log findings without changing outgoing request bodies. |

For `/scan` and `/anonymize`, the runtime whitelist is the combination of `default_whitelist` and any request-level `whitelist`.

Legacy configs using a top-level `[]Config` array are still accepted.

## Supported detectors

| Type | Example | Validation / logic |
|---|---|---|
| `EMAIL` | `foo@example.com` | Regex-based |
| `PHONE` | `+49 171 1234567` | DACH-focused, at least 9 digits |
| `IBAN` | `DE89 3704 0044 0532 0130 00` | MOD-97 checksum |
| `CREDIT_CARD` | `4111-1111-1111-1111` | Luhn check |
| `TAX_ID` | `86 095 742 719` | German tax ID validation |
| `SOCIAL_SECURITY` | `65 180675 B 003` | German social security format |
| `KVNR` | `A123456789` | German health insurance number validation |
| `VAT_ID` | `DE 123 456 789` | German VAT ID validation |
| `PERSONAL_ID` | `C22990047` | German passport / ID style patterns |
| `LICENSE_PLATE` | `M-AB 1234` | German plate formats |
| `DRIVER_LICENSE` | `B123456AB` | Context-aware driver's license detection |
| `ADDRESS` | `Musterstrasse 12, 80331 Muenchen` | DACH street + postal code + city |
| `URL_SECRET` | `?token=abc123` | Sensitive query parameter detection |
| `SECRET` | API keys, JWTs, cloud tokens | Large built-in ruleset |

## Typical use cases

- Protect prompts and file snippets sent from Claude Code
- Offer a local anonymization API for internal tooling
- Run detector tests against sample text before rolling out changes
- Operate in `dry_run` mode first to see what would be masked

## Development

```bash
go build -o privacy-guard-proxy .
go test ./...
```

Project layout:

```text
internal/
├── api/        # Web UI + REST API
├── detector/   # PII and secret detection engine
└── proxy/      # Reverse proxy and masking pipeline
main.go         # Application entry point
config.json     # Runtime configuration
```

Frontend assets are vendored under `internal/api/static/vendor/`, so the Web UI does not depend on external CDNs at runtime.
