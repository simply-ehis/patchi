"""
WebSocket event bus for Patchi web UI.

ConnectionManager tracks all connected clients.
Broadcaster.emit() sends a typed event to every connected client.
Event helpers build correctly-shaped dicts — no raw dict construction elsewhere.
"""

from __future__ import annotations

import json

from fastapi import WebSocket

from patchi.web.ws import (
    manager as _ws_manager,
)

# ── Connection manager ─────────────────────────────────────────────────────────


class ConnectionManager:
    """Tracks active WebSocket connections. Thread-safe for single-process uvicorn."""

    def __init__(self) -> None:
        self._active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._active = [c for c in self._active if c is not ws]

    async def broadcast(self, payload: dict) -> None:
        """Send JSON payload to all connected clients. Drops silently on send error."""
        message = json.dumps(payload)
        dead: list[WebSocket] = []
        for ws in self._active:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._active)


class _WSCompatWrapper:
    """Compatibility wrapper: events.CM API → ws.WSManager API.

    events.py callers use ``await manager.broadcast(payload_dict)``
    while ws.WSManager uses ``await manager.broadcast(event, data)``.
    This wrapper bridges the two.
    """

    async def connect(self, ws: WebSocket) -> None:
        await _ws_manager.connect(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        await _ws_manager.disconnect(ws)

    async def broadcast(self, payload: dict) -> None:
        event = payload.get("event", "")
        data = payload.get("data", {})
        await _ws_manager.broadcast(event, data)

    @property
    def count(self) -> int:
        return _ws_manager.connection_count


manager = _WSCompatWrapper()


# ── Event schema ───────────────────────────────────────────────────────────────


def _evt(event: str, data: dict) -> dict:
    return {"event": event, "data": data}


# Server → client events


def evt_agent_progress(agent: str, progress_pct: int, current_file: str = "") -> dict:
    return _evt(
        "agent.progress",
        {"agent": agent, "progress_pct": progress_pct, "current_file": current_file},
    )


def evt_agent_finding(severity: str, title: str, file: str = "", line: int = 0) -> dict:
    return _evt(
        "agent.finding",
        {"severity": severity, "title": title, "file": file, "line": line},
    )


def evt_agent_completed(agent: str, findings_count: int, report_summary: str = "") -> dict:
    return _evt(
        "agent.completed",
        {"agent": agent, "findings_count": findings_count, "report_summary": report_summary},
    )


def evt_agent_failed(agent: str, reason: str) -> dict:
    return _evt("agent.failed", {"agent": agent, "reason": reason})


def evt_scan_file_found(path: str, file_type: str, purpose: str) -> dict:
    return _evt("brain.scan.file_found", {"path": path, "type": file_type, "purpose": purpose})


def evt_scan_dependency_mapped(from_node: str, to_node: str, dep_type: str) -> dict:
    return _evt(
        "brain.scan.dependency_mapped",
        {"from_node": from_node, "to_node": to_node, "type": dep_type},
    )


def evt_scan_completed(file_count: int, route_count: int, health_score: int) -> dict:
    return _evt(
        "brain.scan.completed",
        {"file_count": file_count, "route_count": route_count, "health_score": health_score},
    )


def evt_scan_failed(reason: str, partial_results: dict) -> dict:
    return _evt("brain.scan.failed", {"reason": reason, "partial_results": partial_results})


def evt_brain_stale(changed_files_count: int) -> dict:
    return _evt("brain.stale", {"changed_files_count": changed_files_count})


def evt_queue_item_added(item_id: str, item_type: str, target: str, position: int) -> dict:
    return _evt(
        "queue.item_added",
        {"item_id": item_id, "type": item_type, "target": target, "position": position},
    )


def evt_queue_item_started(item_id: str) -> dict:
    return _evt("queue.item_started", {"item_id": item_id})


def evt_queue_item_completed(item_id: str, outcome: str) -> dict:
    return _evt("queue.item_completed", {"item_id": item_id, "outcome": outcome})


def evt_queue_item_failed(item_id: str, reason: str) -> dict:
    return _evt("queue.item_failed", {"item_id": item_id, "reason": reason})


def evt_queue_paused(reason: str) -> dict:
    return _evt("queue.paused", {"reason": reason})


def evt_queue_resumed() -> dict:
    return _evt("queue.resumed", {})


def evt_queue_cleared() -> dict:
    return _evt("queue.cleared", {})


def evt_fix_proposed(
    patch_id: str, risk_score: int, confidence_score: int, diff: dict, blast_radius: list
) -> dict:
    return _evt(
        "fix.proposed",
        {
            "patch_id": patch_id,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "diff": diff,
            "blast_radius": blast_radius,
        },
    )


def evt_fix_applying(patch_id: str, file: str, lines_affected: list) -> dict:
    return _evt(
        "fix.applying", {"patch_id": patch_id, "file": file, "lines_affected": lines_affected}
    )


def evt_fix_test_running(patch_id: str, test_type: str) -> dict:
    return _evt("fix.test_running", {"patch_id": patch_id, "test_type": test_type})


def evt_fix_test_passed(patch_id: str) -> dict:
    return _evt("fix.test_passed", {"patch_id": patch_id})


def evt_fix_test_failed(patch_id: str, failure_reason: str) -> dict:
    return _evt("fix.test_failed", {"patch_id": patch_id, "failure_reason": failure_reason})


def evt_fix_rolled_back(patch_id: str, reason: str) -> dict:
    return _evt("fix.rolled_back", {"patch_id": patch_id, "reason": reason})


def evt_fix_rejected_by_user(patch_id: str) -> dict:
    return _evt("fix.rejected_by_user", {"patch_id": patch_id})


def evt_security_scan_started(mode: str) -> dict:
    return _evt("security.scan.started", {"mode": mode})


def evt_security_finding(
    severity: str, type: str, file: str, line: int, cwe: str, description: str
) -> dict:
    return _evt(
        "security.finding",
        {
            "severity": severity,
            "type": type,
            "file": file,
            "line": line,
            "cwe": cwe,
            "description": description,
        },
    )


def evt_security_scan_completed(
    critical_count: int, high_count: int, medium_count: int, low_count: int
) -> dict:
    return _evt(
        "security.scan.completed",
        {
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
        },
    )


def evt_security_threat_detected(threat_type: str, source_ip: str, severity: str) -> dict:
    return _evt(
        "security.threat_detected",
        {"threat_type": threat_type, "source_ip": source_ip, "severity": severity},
    )


def evt_test_suite_started(test_type: str, test_count: int) -> dict:
    return _evt("test.suite.started", {"test_type": test_type, "test_count": test_count})


def evt_test_case_passed(test_name: str, duration_ms: int) -> dict:
    return _evt("test.case.passed", {"test_name": test_name, "duration_ms": duration_ms})


def evt_test_case_failed(test_name: str, error: str, duration_ms: int) -> dict:
    return _evt(
        "test.case.failed", {"test_name": test_name, "error": error, "duration_ms": duration_ms}
    )


def evt_test_browser_flow_started(flow_name: str, steps: list) -> dict:
    return _evt("test.browser.flow_started", {"flow_name": flow_name, "steps": steps})


def evt_test_browser_step_passed(flow_name: str, step: str) -> dict:
    return _evt("test.browser.step_passed", {"flow_name": flow_name, "step": step})


def evt_test_browser_step_failed(flow_name: str, step: str, screenshot_url: str) -> dict:
    return _evt(
        "test.browser.step_failed",
        {"flow_name": flow_name, "step": step, "screenshot_url": screenshot_url},
    )


def evt_test_stress_update(
    users: int, rps: int, p50: float, p95: float, p99: float, error_rate: float
) -> dict:
    return _evt(
        "test.stress.update",
        {"users": users, "rps": rps, "p50": p50, "p95": p95, "p99": p99, "error_rate": error_rate},
    )


def evt_test_stress_break_found(breaking_users: int, breaking_route: str) -> dict:
    return _evt(
        "test.stress.break_found",
        {"breaking_users": breaking_users, "breaking_route": breaking_route},
    )


def evt_test_suite_completed(passed: int, failed: int, coverage_pct: float) -> dict:
    return _evt(
        "test.suite.completed", {"passed": passed, "failed": failed, "coverage_pct": coverage_pct}
    )


def evt_health_score_updated(score: int, previous_score: int, components: dict) -> dict:
    return _evt(
        "health.score_updated",
        {"score": score, "previous_score": previous_score, "components": components},
    )


def evt_health_score_100_estimate(
    cycles_needed: int, estimated_hours: int, estimated_cost: float
) -> dict:
    return _evt(
        "health.score_100_estimate",
        {
            "cycles_needed": cycles_needed,
            "estimated_hours": estimated_hours,
            "estimated_cost": estimated_cost,
        },
    )


def evt_guard_anomaly_detected(
    anomaly_type: str, ip: str, severity: str, signal_data: dict
) -> dict:
    return _evt(
        "guard.anomaly_detected",
        {"type": anomaly_type, "ip": ip, "severity": severity, "signal_data": signal_data},
    )


def evt_guard_ip_escalated(ip: str, old_score: int, new_score: int) -> dict:
    return _evt("guard.ip_escalated", {"ip": ip, "old_score": old_score, "new_score": new_score})


def evt_guard_ip_blocked(ip: str, reason: str, duration: int) -> dict:
    return _evt("guard.ip_blocked", {"ip": ip, "reason": reason, "duration": duration})


def evt_guard_agent_connected(connection_type: str) -> dict:
    return _evt("guard.agent_connected", {"connection_type": connection_type})


def evt_guard_agent_disconnected(last_seen: str, reason: str) -> dict:
    return _evt("guard.agent_disconnected", {"last_seen": last_seen, "reason": reason})


def evt_guard_stats(requests_per_min: int, errors: int, blocked: int, anomalies: int) -> dict:
    return _evt(
        "guard.stats",
        {
            "requests_per_min": requests_per_min,
            "errors": errors,
            "blocked": blocked,
            "anomalies": anomalies,
        },
    )


def evt_security_report(total: int, by_severity: dict, by_owasp: dict) -> dict:
    return _evt(
        "security.report",
        {
            "total_findings": total,
            "by_severity": by_severity,
            "by_owasp": by_owasp,
        },
    )


def evt_notification_sent(channel: str, level: str, message: str) -> dict:
    return _evt("notification.sent", {"channel": channel, "level": level, "message": message})


def evt_notification_failed(channel: str, reason: str) -> dict:
    return _evt("notification.failed", {"channel": channel, "reason": reason})


def evt_system_mode_changed(old_mode: str, new_mode: str) -> dict:
    return _evt("system.mode_changed", {"old_mode": old_mode, "new_mode": new_mode})


def evt_system_key_exhausted(provider: str, switching_to: str) -> dict:
    return _evt("system.key_exhausted", {"provider": provider, "switching_to": switching_to})


def evt_system_low_memory(available_mb: int, action_taken: str) -> dict:
    return _evt("system.low_memory", {"available_mb": available_mb, "action_taken": action_taken})


def evt_system_error(component: str, reason: str, recoverable: bool) -> dict:
    return _evt(
        "system.error", {"component": component, "reason": reason, "recoverable": recoverable}
    )


def evt_queue_updated(depth: int, active: int, paused: bool = False) -> dict:
    return _evt(
        "queue.updated",
        {"depth": depth, "active": active, "paused": paused},
    )


def evt_review_updated(pending_count: int) -> dict:
    return _evt("review.updated", {"pending_count": pending_count})


def evt_ant_spawned(node_id: str, ant_id: str) -> dict:
    return _evt("ant.spawned", {"node_id": node_id, "ant_id": ant_id})


def evt_ant_result(ant_id: str, node_id: str, findings: list[dict]) -> dict:
    return _evt(
        "ant.result",
        {"ant_id": ant_id, "node_id": node_id, "findings": findings},
    )


def evt_ant_rejected(node_id: str, reason: str) -> dict:
    return _evt("ant.rejected", {"node_id": node_id, "reason": reason})


def evt_error(message: str) -> dict:
    return _evt("error", {"message": message})


def evt_status(
    mode: str,
    active_agents: int,
    queue_depth: int,
    brain_fresh: bool,
) -> dict:
    return _evt(
        "status",
        {
            "mode": mode,
            "active_agents": active_agents,
            "queue_depth": queue_depth,
            "brain_fresh": brain_fresh,
        },
    )


# Client to server events (handled by server)
def evt_action_fix_accept(patch_id: str) -> dict:
    return _evt("action.fix_accept", {"patch_id": patch_id})


def evt_action_fix_reject(patch_id: str) -> dict:
    return _evt("action.fix_reject", {"patch_id": patch_id})


def evt_action_fix_undo(patch_id: str) -> dict:
    return _evt("action.fix_undo", {"patch_id": patch_id})


def evt_action_queue_pause() -> dict:
    return _evt("action.queue_pause", {})


def evt_action_queue_resume() -> dict:
    return _evt("action.queue_resume", {})


def evt_action_queue_skip() -> dict:
    return _evt("action.queue_skip", {})


def evt_action_queue_clear() -> dict:
    return _evt("action.queue_clear", {})


def evt_action_spawn_ant(node_id: str) -> dict:
    return _evt("action.spawn_ant", {"node_id": node_id})


def evt_action_mode_change(mode: str) -> dict:
    return _evt("action.mode_change", {"mode": mode})


def evt_action_cancel_scan() -> dict:
    return _evt("action.cancel_scan", {})
