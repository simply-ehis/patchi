"""
Event schema — the universal envelope for everything Patchi detects, routes, or acts on.

Every signal source (HTTP traffic, logs, syscalls, git diffs, agent findings) normalizes
into this schema before reaching the dispatcher. Every action, override, and audit log
entry also uses it. This is the single contract between all pipeline stages.

MITRE ATT&CK v14 technique IDs are used as the primary classification axis because:
- They're stable, versioned, and community-maintained (not invented here)
- They map 1:1 to the specialist agent roster
- Atomic Red Team tests emit known technique_ids, making end-to-end validation tractable
- OWASP/CWE mappings are secondary labels (we maintain the bidirectional map)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

# ── Event severity (extends the Finding severity model) ──────────────────────


class EventSeverity(StrEnum):
    DEBUG = "debug"  # No alerting, diagnostics only
    INFO = "info"  # Informational, never alerts
    LOW = "low"  # Digest-only, no immediate action
    MEDIUM = "medium"  # Worthy of investigation
    HIGH = "high"  # Requires prompt attention
    CRITICAL = "critical"  # Immediate action required

    def sort_key(self) -> int:
        return {
            "debug": 5,
            "info": 4,
            "low": 3,
            "medium": 2,
            "high": 1,
            "critical": 0,
        }[self.value]

    def to_enum(self) -> str:
        return self.value


# ── Event source types ──────────────────────────────────────────────────────


class EventSource(StrEnum):
    """Where the event originated. Each maps to a signal source type."""

    AGENT = "agent"  # A Patchi agent produced a finding
    HTTP_TRAFFIC = "http_traffic"  # Ingress/egress HTTP request
    LOG_LINE = "log_line"  # Application or access log
    SYSCALL = "syscall"  # Host/container syscall (Falco)
    NETWORK_FLOW = "network_flow"  # Network protocol event (Suricata/Zeek)
    DEPENDENCY_SCAN = "dependency"  # Dependency manifest / CVE scan
    SECRET_SCAN = "secret"  # Secret scanning hit
    GIT_EVENT = "git_event"  # Commit, PR, diff, push
    CONFIG_CHANGE = "config"  # Config file or env var change
    HEARTBEAT = "heartbeat"  # System health / uptime check
    USER_ACTION = "user_action"  # Explicit user command or override
    ANOMALY = "anomaly"  # Detected by the anomaly layer


# ── MITRE ATT&CK technique / tactic IDs ──────────────────────────────────────


# Selected ATT&CK technique IDs relevant to Patchi's agent roster.
# v14+ stable IDs; see https://attack.mitre.org/techniques/enterprise/


class TechniqueID(StrEnum):
    INITIAL_ACCESS = "T1190"  # Exploit Public-Facing Application
    EXECUTION = "T1203"  # Exploitation for Client Execution
    PERSISTENCE = "T1505"  # Server Software Component
    DEFENSE_EVASION = "T1562"  # Impair Defenses
    CREDENTIAL_ACCESS = "T1552"  # Unsecured Credentials
    DISCOVERY = "T1046"  # Network Service Discovery
    COLLECTION = "T1567"  # Exfiltration Over Web Service
    COMMAND_AND_CONTROL = "T1071"  # Application Layer Protocol
    EXFILTRATION = "T1048"  # Exfiltration Over Alternative Protocol
    IMPACT = "T1499"  # Endpoint Denial of Service
    RESOURCE_DEVELOPMENT = "T1583"  # Acquire Infrastructure
    INJECTION = "T1055"  # Process Injection
    VALID_ACCOUNTS = "T1078"  # Valid Accounts
    BRUTE_FORCE = "T1110"  # Brute Force
    INPUT_CAPTURE = "T1056"  # Input Capture
    MODIFY_AUTH_PROCESS = "T1556"  # Modify Authentication Process
    STEAL_APPLICATION_ACCESS = "T1528"  # Steal Application Access Token
    SECRETS_FROM_STORE = "T1552.001"  # Credentials in Files / Keychains
    EXPLOIT_PUBLIC_APP = "T1190"  # Exploit Public-Facing Application
    MAN_IN_MIDDLE = "T1557"  # Adversary-in-the-Middle
    TRAFFIC_SIGNALING = "T1573"  # Encrypted Channel
    PROXY = "T1090"  # Proxy
    UNKNOWN = "T9999"  # Unclassified / needs triage
    NONE = "T0000"  # No technique mapping (info/heartbeat)

    @classmethod
    def for_agent_type(cls, agent_type: str) -> TechniqueID:
        mapping = {
            "injection": cls.INJECTION,
            "auth": cls.BRUTE_FORCE,
            "authz": cls.VALID_ACCOUNTS,
            "dependency": cls.RESOURCE_DEVELOPMENT,
            "secret": cls.SECRETS_FROM_STORE,
            "network": cls.TRAFFIC_SIGNALING,
            "runtime": cls.EXECUTION,
            "triage": cls.UNKNOWN,
            "crypto": cls.DEFENSE_EVASION,
            "compliance": cls.IMPACT,
        }
        return mapping.get(agent_type, cls.UNKNOWN)

    @classmethod
    def display_name(cls, tid: str) -> str:
        names = {
            "T1190": "Exploit Public-Facing Application",
            "T1203": "Exploitation for Client Execution",
            "T1505": "Persistent Server Software Component",
            "T1562": "Impair Defenses",
            "T1552": "Unsecured Credentials",
            "T1046": "Network Service Discovery",
            "T1567": "Exfiltration Over Web Service",
            "T1071": "Application Layer Protocol C2",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1499": "Endpoint Denial of Service",
            "T1583": "Acquire Infrastructure",
            "T1055": "Process Injection",
            "T1078": "Valid Accounts",
            "T1110": "Brute Force",
            "T1056": "Input Capture",
            "T1556": "Modify Authentication Process",
            "T1528": "Steal Application Access Token",
            "T1552.001": "Credentials from Files",
            "T1557": "Adversary-in-the-Middle",
            "T1573": "Encrypted Channel",
            "T1090": "Proxy",
            "T9999": "Unclassified",
            "T0000": "None",
        }
        return names.get(tid, "Unknown Technique")


# ── The event envelope ───────────────────────────────────────────────────────


@dataclass
class Event:
    """
    Universal event envelope.

    Every signal in the system normalizes to this shape before entering the pipeline.
    Immutable after creation (consumers should not mutate).

    The `id` is a deterministic hash of the event's key fields so the same external
    signal always produces the same event ID (useful for deduplication). Override with
    `override_id` for synthetic events.
    """

    source: EventSource
    technique_id: TechniqueID | str

    # Core payload
    summary: str  # One-line human-readable description
    severity: EventSeverity = EventSeverity.INFO
    payload: dict[str, Any] = field(default_factory=dict)  # Signal-specific data

    # Routing hints — populated by the detector, consumed by the dispatcher
    suggested_agent: str | None = None  # e.g. "InjectionAgent"
    confidence: float = 0.5  # 0.0–1.0, how sure the detector is

    # Enrichment
    agent_name: str | None = None  # Which agent produced this (if from an agent)
    finding_id: str | None = None  # Link back to a specific Finding if applicable
    cwe_ids: list[str] = field(default_factory=list)
    owasp_category: str = ""

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    source_details: dict[str, str] = field(default_factory=dict)  # host, container, file, repo

    # Audit chain
    parent_event_id: str | None = None  # Which event triggered this one

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "source": self.source.value,
            "technique_id": self.technique_id.value
            if isinstance(self.technique_id, TechniqueID)
            else self.technique_id,
            "summary": self.summary,
            "severity": self.severity.value,
            "payload": self.payload,
            "suggested_agent": self.suggested_agent,
            "confidence": self.confidence,
            "agent_name": self.agent_name,
            "finding_id": self.finding_id,
            "cwe_ids": self.cwe_ids,
            "owasp_category": self.owasp_category,
            "timestamp": self.timestamp,
            "source_details": self.source_details,
            "parent_event_id": self.parent_event_id,
        }

    @property
    def technique_display(self) -> str:
        tid = self.technique_id.value if isinstance(self.technique_id, TechniqueID) else self.technique_id
        return f"{tid} — {TechniqueID.display_name(tid)}"


# ── EventBatch (for bulk processing) ─────────────────────────────────────────


@dataclass
class EventBatch:
    """A time-windowed batch of events for bulk dispatch/audit."""

    events: list[Event] = field(default_factory=list)
    batch_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def by_severity(self) -> dict[str, list[Event]]:
        groups: dict[str, list[Event]] = {}
        for ev in self.events:
            groups.setdefault(ev.severity.value, []).append(ev)
        return groups

    def by_technique(self) -> dict[str, list[Event]]:
        groups: dict[str, list[Event]] = {}
        for ev in self.events:
            tid = ev.technique_id.value if isinstance(ev.technique_id, TechniqueID) else ev.technique_id
            groups.setdefault(tid, []).append(ev)
        return groups

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "created": self.created,
            "count": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }
