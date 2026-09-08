# Patchi API Reference

## REST API (`p web`)

Base URL: `http://localhost:9798/api` (default)

### Status & Config

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Mode, queue depth, brain freshness, health score, AI cost stats |
| GET | `/api/config` | Full config (no secrets) |
| POST | `/api/config` | Update config (single key `{"key":"mode","value":"auto"}` or bulk `{"mode":"auto","queue_mode":"multi"}`) |

### Brain

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/brain/nodes` | Brain Map nodes + edges with per-file finding counts |
| GET | `/api/brain/purpose` | Project purpose + domain (from AI or heuristic) |
| GET | `/api/brain/contract` | Inferred + confirmed contract flows with confidence |
| GET | `/api/findings` | Latest scan findings |
| GET | `/api/health-breakdown` | Health score components (0-100) |

### Scans & Fixes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/action/scan` | Trigger a full scan (async) |
| POST | `/api/action/deep-scan` | Trigger a deep AI scan (async) |
| POST | `/api/action/fix` | Generate fixes for findings |
| GET | `/api/review` | List pending patches |
| POST | `/api/review/accept` | Accept a patch by ID |
| POST | `/api/review/reject` | Reject a patch by ID |
| POST | `/api/review/accept-all` | Accept all pending patches |
| POST | `/api/undo` | Undo the last applied patch |
| POST | `/api/redo` | Redo the last undone patch |

### Security

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/security/quick-scan` | Quick security scan (3 agents) |
| POST | `/api/security/full-scan` | Full security scan (26 agents, orchestrated) |
| GET | `/api/security` | Security findings list |
| GET | `/api/security/report` | Orchestrated report: deduplicated, correlated, OWASP-mapped |

### Testing

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/test/run` | Run tests |
| GET | `/api/tests` | Test results |

### Notifications

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/notifications` | List notification channels |
| POST | `/api/notifications/add` | Add a notification channel |
| POST | `/api/notifications/test` | Send test notification |

### Watch & Model

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/watch/start` | Start file watcher |
| POST | `/api/watch/stop` | Stop file watcher |
| GET | `/api/agents` | List all agents by group |
| GET | `/api/doctor` | Run diagnostics checks |
| GET | `/api/model/status` | AI model status |
| POST | `/api/model/set` | Set AI model |

### Queue

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/queue` | Queue items |
| POST | `/api/queue/pause` | Pause queue |
| POST | `/api/queue/resume` | Resume queue |

### Keys

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/keys` | List configured API keys |
| POST | `/api/keys/add` | Add an API key |
| POST | `/api/keys/remove` | Remove an API key |

### Memory

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/memory` | All memory categories |
| GET | `/api/memory/brain` | Brain knowledge |
| GET | `/api/memory/patches` | Patch history |
| GET | `/api/memory/issues` | Known issues |
| GET | `/api/memory/failed` | Failed patches |
| GET | `/api/memory/scans` | Scan results |
| GET | `/api/memory/restrictions` | Restrictions |
| GET | `/api/memory/tokens` | Dev tokens |

### History & Report

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/history` | Scan and fix history |
| POST | `/api/report` | Export markdown report |

### Ants

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ants` | Active ants list |
| POST | `/api/action/spawn-ant` | Spawn an ant on a node |

---

## WebSocket Events

Connect: `ws://localhost:9798/ws`

### Server → Client

| Event | Data | When |
|-------|------|------|
| `status.update` | `{mode, queue_depth, brain_fresh, health_score, framework}` | Initial state on connect + state change |
| `scan.progress` | `{phase, current, total, message}` | Scan progress tick |
| `brain.scan.started` | `{file_count_estimate}` | Scan begins |
| `brain.scan.file_found` | `{path, type, purpose}` | File discovered |
| `brain.scan.completed` | `{file_count, route_count}` | Scan finishes |
| `brain.scan.failed` | `{reason}` | Scan fails |
| `scan.complete` | `{total_findings}` | All scanners done |
| `agent.started` | `{agent, file}` | Agent begins |
| `agent.done` | `{agent, findings, file}` | Agent completes |
| `agent.finding` | `{severity, title, file, line}` | Finding found |
| `fix.proposed` | `{patch_id, risk_score}` | Patch created |
| `fix.applied` | `{patch_id, outcome}` | Patch applied |
| `fix.rolled_back` | `{patch_id, reason}` | Patch reverted |
| `ant.spawned` | `{node_id, ant_id}` | Ant created |
| `ant.result` | `{ant_id, node_id, findings}` | Ant returned |
| `ant.rejected` | `{node_id, reason}` | Ant rejected |
| `test.suite.started` | `{test_type}` | Tests begin |
| `test.suite.completed` | `{passed, failed}` | Tests finish |
| `queue.update` | `{depth, active}` | Queue depth changed |
| `ws.connected` | `{}` | Reconnected |

### Client → Server

| Action | Payload | Effect |
|--------|---------|--------|
| `action.spawn_ant` | `{node_id}` | Spawn ant on a brain map node |

---

## Configuration (`config.json`)

Keys stored in `.patchi/config.json`:

```json
{
  "mode": "confirm | auto | autopilot",
  "theme": "dark | light",
  "risk_threshold": 30,
  "ai": {
    "local_model_name": null,
    "keys": [],
    "cost_limit_enabled": false,
    "cost_limit": null
  },
  "notifications": [],
  "quiet_hours": {
    "enabled": false,
    "start": "22:00",
    "end": "08:00"
  }
}
```

CLI equivalents: `p mode`, `p settings`, `p key add`, `p notify add`.

---

## CLI Command Reference

```text
p init             # Initialize project
p scan             # Run brain scan
p fix              # Generate fixes
p review           # Review pending patches
p security         # Run security scan
p test             # Run tests
p chat             # Interactive chat
p notify           # Manage notifications
p web              # Launch web UI
p watch            # Start file watcher
p status           # Show state
p key              # Manage API keys
p mode             # Set mode
p queue            # Manage queue
p memory           # View memory
p patch            # Manage patches
p undo/redo        # Undo/redo fixes
p agents           # List agents
p restrict         # Set restrictions
p hosted           # Hosted mode
p report           # Export report
p doctor           # Run diagnostics
p model            # AI model management
p settings         # Show/modify settings
p access           # Show/set access flags
```
