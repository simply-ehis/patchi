# Patchi Hosted Mode — Deployment Guide

Patchi's hosted mode monitors your live application's log stream and provides real-time anomaly detection, IP reputation checking, and automatic threat escalation. **You deploy it on your own server** — it watches your logs and guards your app.

## Quick Start

### Option 1: Direct Install (Recommended for single servers)

```bash
# Install patchi
pip install patchi

# Configure hosted mode (interactive)
patchi hosted init

# Start the guard daemon (with auto-restart)
patchi hosted daemon --guard
```

### Option 2: Docker

```bash
# Build
docker build -t patchi-guard .

# Run (mount your log directory)
docker run -d \
  --name patchi-guard \
  -v /var/log/nginx:/var/log/nginx:ro \
  -v patchi-data:/data \
  patchi-guard
```

### Option 3: Systemd (Production)

```bash
# Run the setup script
sudo bash deploy/setup.sh

# Configure
sudo -u patchi /opt/patchi/venv/bin/patchi hosted init

# Start
sudo systemctl start patchi-guard
sudo systemctl enable patchi-guard
```

---

## Configuration

After running `patchi hosted init`, your config is stored in `.patchi/config.json`:

```json
{
  "hosted": {
    "enabled": true,
    "log_path": "/var/log/nginx/access.log",
    "log_format": "nginx",
    "escalate": true,
    "rate_spike_rps": 50,
    "brute_force_auth": 20,
    "scanner_paths": 30,
    "error_rate_pct": 0.40,
    "ip_whitelist": ["127.0.0.1", "::1"]
  }
}
```

### Supported Log Formats

| Format | Command | Description |
|--------|---------|-------------|
| `nginx` | Combined log format | `127.0.0.1 - - [time] "GET /path" 200 ...` |
| `apache` | Common/Combined format | Same as nginx |
| `caddy` | JSON structured | Caddy's `http.log.access` |
| `uvicorn` | Access log format | `127.0.0.1:port - "GET /path" 200` |
| `gunicorn` | Access log format | Same as uvicorn |
| `cloudflare` | JSON API | Cloudflare log push |
| `json` | Generic JSON | Any JSON with `status`, `path`, `ip` fields |

### Configurable Thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| `rate_spike_rps` | 50 | Requests/second to trigger rate spike alert |
| `brute_force_auth` | 20 | Auth attempts in 60s to trigger brute force |
| `scanner_paths` | 30 | Distinct paths in 60s to trigger scanner sweep |
| `error_rate_pct` | 0.40 | Error rate (0-1) to trigger error spike |
| `ip_whitelist` | `[]` | IPs excluded from anomaly detection |

---

## Commands Reference

| Command | Description |
|---------|-------------|
| `p hosted init` | Interactive setup |
| `p hosted worker` | Start log watcher (foreground) |
| `p hosted daemon` | Start with auto-restart + health checks |
| `p hosted daemon --guard` | Daemon + anomaly detection |
| `p hosted guard` | Start guard with anomaly detection |
| `p hosted status` | Show watchlist + audit log |
| `p hosted status --json` | Output as JSON |
| `p hosted logs` | Stream audit log |
| `p hosted block <ip>` | Manually block an IP |
| `p hosted unblock <ip>` | Unblock an IP |
| `p hosted token add` | Generate admin token |
| `p hosted token list` | List active tokens |
| `p hosted token revoke <id>` | Revoke a token |
| `p hosted stop` | Stop running daemon |
| `p hosted disconnect` | Clear hosted config |

---

## What It Does

### Anomaly Detection (Two Layers)

1. **Statistical** — Rolling 60s windows detect:
   - Request rate spikes (>50 req/s)
   - Brute force on auth endpoints (>20 attempts/60s)
   - Scanner sweeps (>30 distinct paths/60s)
   - High error rates (>40%)
   - Injection probes (SQLi, XSS, path traversal, JNDI)

2. **ML (IsolationForest)** — Trains on baseline, catches outliers statistics miss. Requires `scikit-learn`.

### IP Reputation

- Loads public blocklists (abuse.ch, firehol)
- Auto-blocks IPs seen on 3+ blocklists
- Manual block/unblock via CLI

### Watchlist Scoring

- Per-IP threat scores with time-decay (reset after 1h silence)
- Escalation at HIGH (50) and CRITICAL (100) thresholds
- Notifications via configured channels (Slack, Discord, email, webhook)

---

## Architecture

```
Your App → writes logs → /var/log/nginx/access.log
                              ↓
                    Patchi hosted worker (tails the file)
                              ↓
                    Parse → StatisticalDetector + MLDetector
                              ↓
                    findings → WatchlistTracker (per-IP scoring)
                              ↓
                    escalation → Notifier (Slack/Discord/email)
                              ↓
                    audit → .patchi/hosted/audit.log
```

---

## Docker Compose Example

```yaml
version: "3.8"
services:
  guard:
    build: .
    volumes:
      - /var/log/nginx:/var/log/nginx:ro
      - patchi-data:/data
    restart: unless-stopped
    environment:
      - PATCHI_ROOT=/data

volumes:
  patchi-data:
```

---

## Security Notes

- Admin tokens use HMAC-SHA256 with a per-installation random key
- Tokens are never stored in plaintext — only hashes persist
- Audit logs are rotated at 5MB with 3 backups
- IP reputation data is stored locally (no external API calls at runtime)
