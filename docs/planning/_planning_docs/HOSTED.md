# Patchi Hosted Mode

Live monitoring, defense pipeline, and guard for deployed applications.

## Overview

Hosted mode provides three defense layers:

1. **Runtime Request Interceptor** (ASGI middleware) — inspects every HTTP request in real time:
   - SQLi, XSS, SSTI, command injection detection in path/body
   - Rate spike detection per IP (>50 req/s)
   - Known malicious IP blocking (configurable threshold, default 0.7)
   - Configurable exclude paths (/health, /metrics, /static)
2. **DetectionPipeline + DefenseLayer** (triggered via `--pipeline`) — auto-fixes code, rotates secrets, blocks IPs, patches configs, updates dependencies
3. **Anomaly detection** — log stream analysis:
   - Statistical anomaly detection — request rate spikes, error rate spikes, status code distribution shifts
   - ML anomaly detection — IsolationForest on request feature vectors
   - IP reputation — block/unblock IPs, track repeat offenders
   - Watchlist tracking — monitor known threat patterns
   - Audit logging — every action recorded for forensic analysis

## Quick Start

```bash
# 1. Initialize hosted mode (interactive setup)
p hosted init

# 2. Start the background worker
p hosted worker

# 3. Check status
p hosted status
```

## Commands

### `p hosted init`
Interactive setup for hosted mode:
- Log file path (nginx, apache, uvicorn, gunicorn, caddy, cloudflare)
- Worker configuration
- Notification channels

### `p hosted worker`
Start the background log-watching worker:
- Watches the configured log file
- Parses each line using the appropriate parser
- Runs anomaly detection on every new line
- Escalates through notification system when thresholds are crossed

### `p hosted guard`
Start live guard with anomaly detection + watchlist:
- Statistical detectors (rolling windows)
- ML detector (IsolationForest)
- IP reputation tracking
- Watchlist monitoring

### `p hosted token add`
Generate a new admin API token (plaintext shown once). Tokens authenticate automated tools against the hosted API.

### `p hosted token list`
List all active tokens.

### `p hosted token revoke <id>`
Revoke a token by ID.

### `p hosted status`
Show watchlist top threats and audit log summary:
- Current threat level
- Top offending IPs
- Recent anomaly detections
- Audit log entries

### `p hosted logs`
Stream the audit log in real time:
- Follow mode (like `tail -f`)
- Filter by severity
- Filter by IP

### `p hosted token add`
Generate a new admin token (shown once):
- 32-byte random hex string
- HMAC-SHA256 hash stored
- Plaintext shown once, cannot be recovered

### `p hosted token list`
List all active tokens:
- Token ID
- Name
- Created at
- Last used

### `p hosted token revoke <id>`
Revoke a token by ID:
- Removes from storage
- Invalidates immediately

### `p hosted block <ip>`
Block an IP address:
- Added to blocklist
- All requests from this IP are flagged

### `p hosted unblock <ip>`
Unblock an IP address:
- Removed from blocklist
- Requests resume normal processing

### `p hosted disconnect`
Clear hosted mode config:
- Removes all hosted configuration
- Stops background workers
- Clears token storage

## Log Parsers

Supported log formats:
- **nginx** — Combined log format
- **apache** — Common/Combined log format
- **uvicorn** — Uvicorn access logs
- **gunicorn** — Gunicorn access logs
- **caddy** — Caddy JSON logs
- **cloudflare** — Cloudflare JSON logs
- **generic** — JSON structured logs

## Anomaly Detection

### Statistical Detectors
- **Request rate** — Rolling window rate tracking
- **Error rate** — HTTP error ratio monitoring
- **Status code distribution** — Shifts in response codes
- **Path enumeration** — Scanning/brute-force patterns

### ML Detector
- **IsolationForest** — Unsupervised anomaly detection
- **Features** — Request rate, error rate, path diversity, user-agent entropy
- **Training** — Online learning from live traffic

## Configuration

Hosted mode config stored in `.patchi/hosted/`:
- `config.json` — Worker settings, log path
- `tokens.json` — Admin tokens (hashed)
- `.secret` — HMAC key for token validation
- `audit.log` — Action audit trail
- `blocklist.json` — Blocked IPs
- `watchlist.json` — Monitored patterns

## Architecture

```
                     ┌──────────────────────────────────────────┐
                     │  REQUEST INTERCEPTOR (ASGI middleware)    │
                     │  ────────────────────────────────         │
                     │  Path/body injection scan → confidence    │
                     │  Rate spike detection → threat IP cache   │
                     │  Block if confidence >= threshold (0.7)   │
                     └──────────────────┬───────────────────────┘
                                        │
                     ┌──────────────────▼───────────────────────┐
                     │  DEFENSE PIPELINE (p scan --pipeline)     │
                     │  ──────────────────────────────           │
                     │  40 Layer 1 agents → ConfidenceGate      │
                     │  HIGH → DefenseLayer (12 action types)   │
                     │  MEDIUM → Layer 2 AI Orchestrator        │
                     │  LOW → human review / discard            │
                     └──────────────────┬───────────────────────┘
                                        │
Log File → Parser → Anomaly Detection → Notification → User / Web UI
                ↓
           Audit Log
                ↓
           IP Reputation
                ↓
           Watchlist
```

## Security

- Tokens are HMAC-SHA256 hashed (plaintext never stored)
- Audit log is append-only
- Blocklist is persistent across restarts
- All actions logged for forensic analysis
