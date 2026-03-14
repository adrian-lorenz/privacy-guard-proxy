# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o privacy-guard-proxy .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/privacy-guard-proxy .

# Config and log directories are mounted as volumes
RUN mkdir -p /app/logs

EXPOSE 9880 9881

ENTRYPOINT ["/app/privacy-guard-proxy"]
