# Proxy Key Monitor

Monitors proxy keys from a Remnawave subscription by actually connecting through Xray, then pushes results to Uptime Kuma.

## Setup

1. Copy `.env.example` to `.env` and fill in your values
2. `docker compose up -d --build`

## Environment

| Variable | Description |
|----------|-------------|
| `SUBSCRIPTION_URL` | Remnawave subscription URL |
| `UPTIME_KUMA_URL` | Uptime Kuma instance URL |
| `UPTIME_KUMA_USER` | Uptime Kuma login |
| `UPTIME_KUMA_PASS` | Uptime Kuma password |
| `CHECK_INTERVAL` | Seconds between checks (default: 60) |
