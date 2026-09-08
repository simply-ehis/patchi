"""
Shared constants for Patchi.
Every magic string lives here. Nothing is scattered across modules.
"""

import os
from enum import StrEnum


def is_offline() -> bool:
    """True when PATCHI_OFFLINE=1 (set by `p scan --offline` / CI gate).

    Offline mode is a hard contract: NO network calls of any kind — not just
    AI provider calls. Network-probing agents (CVE/OSV lookups, live app
    crawling, runtime validation) must honor this or `--offline` silently
    leaks traffic and hangs on blocked egress.
    """
    return bool(os.environ.get("PATCHI_OFFLINE"))


# ── Modes ─────────────────────────────────────────────────────────────────────


class Mode(StrEnum):
    CONFIRM = "confirm"  # every action requires approval
    AUTO = "auto"  # safe fixes auto-apply, risky ones ask
    AUTOPILOT = "autopilot"  # full trust, Patchi decides everything

    def label(self) -> str:
        return self.value.upper()

    def color(self) -> str:
        return {"confirm": "cyan", "auto": "yellow", "autopilot": "green"}[self.value]


# ── Queue modes ────────────────────────────────────────────────────────────────


class QueueMode(StrEnum):
    SINGLE = "single"  # one task at a time
    MULTI = "multi"  # auto-scaled parallel
    OFF = "off"  # full speed, no queue

    def description(self) -> str:
        return {
            "single": "One task at a time. Lowest resource use. Safe on any device.",
            "multi": "Parallel tasks. Auto-scaled to your hardware.",
            "off": "Full speed. Everything runs immediately.",
        }[self.value]


# ── Queue item states ──────────────────────────────────────────────────────────


class QueueItemState(StrEnum):
    WAITING = "waiting"
    ACTIVE = "active"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Restriction types ──────────────────────────────────────────────────────────


class RestrictionType(StrEnum):
    NO_TOUCH = "no_touch"  # Patchi never reads, scans, or modifies
    SCAN_ONLY = "scan_only"  # read and report, never fix
    SENSITIVE = "sensitive"  # acknowledges existence, never reads contents


# ── Memory categories ──────────────────────────────────────────────────────────


class MemoryCategory(StrEnum):
    BRAIN = "brain"
    PATCHES = "patches"
    FAILED = "failed"
    SCANS = "scans"
    ISSUES = "issues"
    RESTRICTIONS = "restrictions"
    TOKENS = "tokens"
    LAYERS = "layers"
    CHARTER = "charter"


# ── Risk levels ────────────────────────────────────────────────────────────────


class RiskLevel(StrEnum):
    LOW = "low"  # 0–30:  safe to auto-apply
    MEDIUM = "medium"  # 31–60: logic changes, requires review in confirm mode
    HIGH = "high"  # 61–100: auth, payments, data — always ask

    @staticmethod
    def from_score(score: int) -> "RiskLevel":
        if score <= 30:
            return RiskLevel.LOW
        if score <= 60:
            return RiskLevel.MEDIUM
        return RiskLevel.HIGH

    def color(self) -> str:
        return {"low": "green", "medium": "yellow", "high": "red"}[self.value]


# ── Device tiers ───────────────────────────────────────────────────────────────


class DeviceTier(StrEnum):
    LOW = "low"  # < 4 GB RAM
    MID = "mid"  # 4–16 GB
    HIGH = "high"  # 16 GB+

    def max_parallel_agents(self) -> int:
        return {"low": 3, "mid": 8, "high": 20}[self.value]

    def default_fps(self) -> int:
        return {"low": 30, "mid": 60, "high": 60}[self.value]

    def max_brain_map_nodes(self) -> int:
        return {"low": 100, "mid": 500, "high": 0}[self.value]  # 0 = unlimited

    def max_ants(self) -> int:
        return {"low": 50, "mid": 200, "high": 0}[self.value]  # 0 = unlimited


# ── Paths ──────────────────────────────────────────────────────────────────────

PATCHI_DIR = ".patchi"
CONFIG_FILE = f"{PATCHI_DIR}/config.json"
MEMORY_DIR = f"{PATCHI_DIR}/memory"
SNAPSHOT_DIR = f"{PATCHI_DIR}/snapshots"
QUEUE_FILE = f"{PATCHI_DIR}/queue.json"

MEMORY_FILES: dict[MemoryCategory, str] = {
    MemoryCategory.BRAIN: f"{MEMORY_DIR}/brain.json",
    MemoryCategory.PATCHES: f"{MEMORY_DIR}/patches.json",
    MemoryCategory.FAILED: f"{MEMORY_DIR}/failed_patches.json",
    MemoryCategory.SCANS: f"{MEMORY_DIR}/scan_results.json",
    MemoryCategory.ISSUES: f"{MEMORY_DIR}/known_issues.json",
    MemoryCategory.RESTRICTIONS: f"{MEMORY_DIR}/restrictions.json",
    MemoryCategory.TOKENS: f"{MEMORY_DIR}/dev_tokens.json",
    MemoryCategory.LAYERS: f"{MEMORY_DIR}/layers.json",
    MemoryCategory.CHARTER: f"{MEMORY_DIR}/charter.json",
}

# ── Queue limits ───────────────────────────────────────────────────────────────

QUEUE_WARN_DEPTH = 40
QUEUE_MAX_DEPTH = 50

# ── AI provider registry ──────────────────────────────────────────────────────
# Single source of truth for all provider base URLs and default models.
# Every module that needs provider info imports from here.

PROVIDERS: dict[str, dict] = {
    "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini", "format": "openai"},
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-20250514",
        "format": "anthropic",
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "model": "gemini-2.0-flash",
        "format": "openai",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "format": "openai",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "model": "mistral-small-latest",
        "format": "openai",
    },
    "cohere": {"base_url": "https://api.cohere.ai/v2", "model": "command-r", "format": "openai"},
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "model": "meta-llama/Llama-3-70b-chat-hf",
        "format": "openai",
    },
    "fireworks": {
        "base_url": "https://api.fireworks.ai/inference/v1",
        "model": "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "format": "openai",
    },
    "perplexity": {
        "base_url": "https://api.perplexity.ai",
        "model": "llama-3.1-sonar-small-128k-online",
        "format": "openai",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "format": "openai",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "format": "openai",
    },
    "xai": {"base_url": "https://api.x.ai/v1", "model": "grok-2", "format": "openai"},
    "nvidia": {
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model": "meta/llama-3.1-70b-instruct",
        "format": "openai",
    },
    "huggingface": {
        "base_url": "https://api-inference.huggingface.co/v1",
        "model": "meta-llama/Llama-3.3-70B-Instruct",
        "format": "openai",
    },
    "pollinations": {
        "base_url": "https://gen.pollinations.ai/v1",
        "model": "openai",
        "format": "openai",
    },
}

# ── AI defaults ───────────────────────────────────────────────────────────────

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = OLLAMA_BASE_URL + "/api/generate"
OLLAMA_TAGS_URL = OLLAMA_BASE_URL + "/api/tags"
ANTHROPIC_API_VERSION = "2023-06-01"
HTTP_REQUEST_TIMEOUT = 60
HTTP_REQUEST_TIMEOUT_SHORT = 15
DEFAULT_MAX_TOKENS = 2000
DEFAULT_TEMPERATURE = 0.3

# ── Budget thresholds ─────────────────────────────────────────────────────────

BUDGET_WARN_PCT = 75
BUDGET_CRITICAL_PCT = 90

# ── Brain ──────────────────────────────────────────────────────────────────────

BRAIN_FRESHNESS_THRESHOLD = 50

# ── Misc ───────────────────────────────────────────────────────────────────────

PATCHI_VERSION = "0.7.5"
