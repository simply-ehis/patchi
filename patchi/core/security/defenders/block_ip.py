"""Adapter: block_ip — block IP via OS firewall and persist to .patchi/blocked_ips.json."""

from __future__ import annotations

import json
import logging
import subprocess

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.block_ip")


class BlockIpAdapter(BaseAdapter):
    """Block an IP address via OS firewall (hosted mode only)."""

    action_type = "block_ip"

    def execute(self, action: DefenseAction) -> DefendResult:
        ip = action.target
        if not ip:
            return DefendResult(
                action="skipped",
                reason="No IP address to block",
                defense_action=action,
            )

        blocked_path = self.root / ".patchi" / "blocked_ips.json"
        blocked: list = []
        if blocked_path.exists():
            try:
                blocked = json.loads(blocked_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("BlockIpAdapter read failed: %s", e)
                blocked = []
        if ip not in blocked:
            blocked.append(ip)
        blocked_path.parent.mkdir(parents=True, exist_ok=True)
        blocked_path.write_text(json.dumps(blocked, indent=2), encoding="utf-8")

        try:
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return DefendResult(
                    action="applied",
                    reason=f"Blocked IP {ip} via iptables (persisted to .patchi/blocked_ips.json)",
                    defense_action=action,
                )
            else:
                return DefendResult(
                    action="applied",
                    reason=f"Blocked IP {ip} persisted to .patchi/blocked_ips.json (iptables unavailable:"
                    f" {result.stderr[:100]})",
                    defense_action=action,
                )
        except FileNotFoundError:
            return DefendResult(
                action="applied",
                reason=f"Blocked IP {ip} persisted to .patchi/blocked_ips.json (iptables not available)",
                defense_action=action,
            )
        except subprocess.TimeoutExpired:
            return DefendResult(
                action="applied",
                reason=f"Blocked IP {ip} persisted to .patchi/blocked_ips.json (iptables timed out)",
                defense_action=action,
            )
