![img.png](img.png)

# privacy-guard-proxy

A local proxy that sits between [Claude Code](https://claude.ai/code) and the Anthropic API and automatically masks PII in every request before it leaves your machine.

Names, email addresses, IBANs, and other sensitive data are replaced with placeholders like `[NAME_1]` or `[EMAIL_1]` — Claude never sees the real values.

## How it works

```
Claude Code  →  privacy-guard-proxy  →  privacy-guard (PII detection)  →  Anthropic API
```

Every outgoing request is intercepted. User messages, tool results, and file contents are scanned for PII and anonymised before being forwarded upstream.

## Requirements

- [privacy-guard](https://github.com/adrian-lorenz/privacy-guard) running locally

## Quick start

```bash
# 1. Start privacy-guard (see its README)

# 2. Start the proxy
./privacy-guard-proxy

# 3. Point Claude Code at the proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:9880
claude
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
      "url": "http://localhost:8090",
      "api_key": "pg_...",
      "detectors": ["EMAIL", "IBAN", "NAME"],
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
| `privacy_guard.url` | URL of the privacy-guard service |
| `privacy_guard.api_key` | API key for privacy-guard (optional) |
| `privacy_guard.detectors` | PII types to detect — empty means all |
| `privacy_guard.whitelist` | Terms to never mask |

## What gets masked

| Content | Masked |
|---|---|
| User messages | ✅ |
| File contents (via tool results) | ✅ |
| Tool inputs (e.g. Write, Edit) | ✅ |
| System prompt | ✗ (contains model instructions, not user data) |
| Assistant responses | ✗ |

## Build

```bash
go build -o privacy-guard-proxy .
```
