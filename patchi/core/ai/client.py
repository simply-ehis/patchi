"""
Unified AI client for Patchi agents.

Supports:
  - System message + user message (two-role prompting)
  - Local Ollama, OpenAI-compatible APIs, Anthropic
  - Structured JSON output (with fallback parsing)
  - Automatic key rotation across configured providers
  - Offline fallback (returns None, never crashes)
  - Retry with exponential backoff for transient failures
"""

from __future__ import annotations

import json
import random

# ── Public API ─────────────────────────────────────────────────────────────────
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, TypeVar

from loguru import logger

from patchi.core.ai.cost_tracker import estimate_tokens, track
from patchi.core.constants import (
    ANTHROPIC_API_VERSION,
    DEFAULT_MAX_TOKENS,
    DEFAULT_TEMPERATURE,
    HTTP_REQUEST_TIMEOUT,
    OLLAMA_GENERATE_URL,
)

_log = logging.getLogger("patchi.core.client")

# ── Retry configuration ─────────────────────────────────────────────────────────
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_MAX_DELAY = 30.0  # seconds
DEFAULT_BACKOFF_MULTIPLIER = 2.0
DEFAULT_JITTER = 0.1  # 10% jitter

# ── Circuit breaker lock ──────────────────────────────────────────────────────────
# Protects circuit breaker state updates
_ai_call_lock = __import__("threading").Lock()

# ── Circuit breaker ─────────────────────────────────────────────────────────────
# Stops AI calls entirely after N consecutive failures (saves time on dead APIs).
_CIRCUIT_BREAKER_THRESHOLD = 3  # consecutive failures before opening
_circuit_failures: int = 0
_circuit_open: bool = False
_circuit_skip_count: int = 0  # rate-limit circuit breaker debug spam

T = TypeVar("T")


def _is_retryable_error(e: Exception) -> bool:
    """Determine if an error is retryable (transient)."""
    if isinstance(e, urllib.error.HTTPError):
        # Retry on 429 (rate limit), 5xx (server errors)
        return e.code in (429, 500, 502, 503, 504)
    if isinstance(e, urllib.error.URLError):
        # Retry on connection errors, timeouts
        return True
    if isinstance(e, TimeoutError):
        return True
    if isinstance(e, ConnectionError):
        return True
    return False


def _record_ai_success() -> None:
    """Record a successful AI call, reset circuit breaker."""
    global _circuit_failures, _circuit_open
    with _ai_call_lock:
        _circuit_failures = 0
        _circuit_open = False


def _record_ai_failure() -> bool:
    """Record a failure. Returns True if circuit is now open (stop calling)."""
    global _circuit_failures, _circuit_open
    with _ai_call_lock:
        _circuit_failures += 1
        if _circuit_failures >= _CIRCUIT_BREAKER_THRESHOLD:
            _circuit_open = True
            logger.warning(
                "AI circuit breaker OPEN after {} consecutive failures — "
                "skipping remaining AI calls this scan",
                _circuit_failures,
            )
        return _circuit_open


def reset_ai_circuit_breaker() -> None:
    """Reset the circuit breaker. Call at the start of each new scan."""
    global _circuit_failures, _circuit_open
    with _ai_call_lock:
        _circuit_failures = 0
        _circuit_open = False


def _retry_with_backoff(
    func: Callable[[], T],
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    backoff_multiplier: float = DEFAULT_BACKOFF_MULTIPLIER,
    jitter: float = DEFAULT_JITTER,
    timeout_remaining: Callable[[], float | None] | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> T | None:
    """
    Execute a function with exponential backoff retry logic.
    Respects the global circuit breaker.
    """
    def _progress(msg: str) -> None:
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    # Circuit breaker: stop immediately if API is dead
    if _circuit_open:
        global _circuit_skip_count
        _circuit_skip_count += 1
        if _circuit_skip_count <= 1 or _circuit_skip_count % 100 == 0:
            logger.debug("AI circuit breaker open — skipping call (x%d)", _circuit_skip_count)
        return None
    
    delay = base_delay
    last_error = None
    
    for attempt in range(max_retries + 1):
        # Check timeout budget
        if timeout_remaining is not None:
            remaining = timeout_remaining()
            if remaining is not None and remaining <= 0:
                logger.debug("Retry budget exhausted")
                return None
        
        try:
            result = func()
            if result is not None:
                _record_ai_success()
            return result
        except Exception as e:
            last_error = e
            
            if attempt < max_retries and _is_retryable_error(e):
                jitter_amount = delay * jitter * (2 * random.random() - 1)
                actual_delay = min(delay + jitter_amount, max_delay)
                
                _progress(f"Retrying in {actual_delay:.1f}s... (attempt {attempt + 2}/{max_retries + 1})")
                logger.debug(
                    "Retryable error (attempt {}/{}): {}. Retrying in {:.1f}s...",
                    attempt + 1, max_retries + 1, e, actual_delay,
                )
                
                time.sleep(actual_delay)
                delay *= backoff_multiplier
            else:
                # Non-retryable error or max retries reached
                logger.debug("Non-retryable error or max retries reached: {}", e)
                break
    
    # Record failure for circuit breaker
    _record_ai_failure()
    return None


def _ensure_env_loaded(root: str | None = None) -> None:
    """Load .patchi/.env into os.environ if not already loaded."""
    _marker = "_PATCHI_ENV_LOADED"
    if os.environ.get(_marker):
        return
    try:
        if root is None:
            from patchi.core.config import find_project_root

            r = find_project_root()
        else:
            from pathlib import Path

            r = Path(root)
        if r is None:
            return
        env_file = r / ".patchi" / ".env"
        if env_file.exists():
            raw = env_file.read_text(encoding="utf-8")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {}
                for line in raw.strip().splitlines():
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        data[k.strip()] = v.strip()
            for key, value in data.items():
                if key and key not in os.environ:
                    os.environ[key] = str(value)
        os.environ[_marker] = "1"
    except Exception as e:
        _log.warning("_ensure_env_loaded failed: %s", e)


def call_ai(
    config: dict,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    timeout: float | None = None,
    root: Path | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> str | None:
    """
    Send a system+user prompt to the configured AI.
    Returns the response text, or None if no AI is available / call fails.

    Priority: local Ollama → configured API keys → None.

    Honors PATCHI_OFFLINE=1 (set by `p scan --offline`): returns None without
    making ANY network call — the flag's documented "static analysis only, zero
    token cost" contract.

    `timeout` bounds the ENTIRE call (all providers tried, poll loops included),
    so a hung provider can never freeze a scan or leave a worker thread alive
    indefinitely. None = no overall deadline (per-request socket timeouts only).
    
    `progress_callback`: Optional callback(message) invoked during long-running
    operations (e.g., "Contacting provider...", "Retrying in 2s...").
    """
    if os.environ.get("PATCHI_OFFLINE"):
        return None

    # Circuit breaker: skip entirely if API is dead
    if _circuit_open:
        global _circuit_skip_count
        _circuit_skip_count += 1
        if _circuit_skip_count <= 1 or _circuit_skip_count % 100 == 0:
            logger.debug("AI circuit breaker open — skipping call (x%d)", _circuit_skip_count)
        return None

    deadline = time.monotonic() + timeout if timeout is not None else None

    def _remaining() -> float | None:
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())

    _ensure_env_loaded()
    ai_config = config.get("ai", {})
    
    def _progress(msg: str) -> None:
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    # ── Resolve root from tenant context if not provided ─────────────────
    if root is None:
        try:
            from patchi.core.tenant import get_current_tenant_root

            root = get_current_tenant_root()
        except Exception as _exc:
            _log.warning('call_ai failed: %s', _exc)

    # ── Cost-aware model routing ───────────────────────────────────────────
    # Use ModelRouter to select optimal model based on prompt complexity
    try:
        from patchi.core.ai.model_router import TaskComplexity, get_model_router

        _router = get_model_router(config, root=root)
        # Estimate complexity from prompt length
        total_len = len(system_prompt) + len(user_prompt)
        if total_len < 500:
            complexity = TaskComplexity.SIMPLE
        elif total_len < 2000:
            complexity = TaskComplexity.MODERATE
        elif total_len < 5000:
            complexity = TaskComplexity.COMPLEX
        else:
            complexity = TaskComplexity.CRITICAL
        routed_model = _router.select_model(complexity=complexity)
        # Override the model in config for this call
        ai_config = dict(ai_config)
        ai_config["_routed_model"] = routed_model
    except Exception as _exc:
        _log.debug("model routing skipped: %s", _exc)

    # Try local Ollama first
    local_model = ai_config.get("local_model_name")
    if local_model:
        result = _call_ollama(
            local_model, system_prompt, user_prompt, max_tokens, temperature, _remaining(), _progress
        )
        if result:
            return result

    # Try configured API keys in order
    keys = ai_config.get("keys", [])
    for key_cfg in keys:
        if key_cfg.get("status") == "error":
            continue
        env_var = key_cfg.get("env_var", "")
        api_key = os.environ.get(env_var, "")
        if not api_key:
            continue

        fmt = key_cfg.get("format", "openai")
        base_url = key_cfg.get("base_url", "https://api.openai.com/v1")
        # Use routed model if available, else fall back to configured model
        model = ai_config.get("_routed_model") or key_cfg.get("model", "gpt-4o-mini")

        if fmt == "anthropic":
            result = _call_anthropic(
                api_key, base_url, model, system_prompt, user_prompt, max_tokens, _remaining(), _progress
            )
        else:
            result = _call_openai_compat(
                api_key,
                base_url,
                model,
                system_prompt,
                user_prompt,
                max_tokens,
                temperature,
                _remaining(),
                _progress,
            )

        if result:
            logger.debug(f"AI call succeeded via {key_cfg.get('name', 'unknown')} ({model})")
            return result

    return None


def call_ai_structured(
    config: dict,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = 0.2,
    progress_callback: Callable[[str], None] | None = None,
) -> dict | list | None:
    """
    Call AI and parse the response as JSON.
    Returns parsed JSON or None.
    """
    raw = call_ai(config, system_prompt, user_prompt, max_tokens, temperature, progress_callback=progress_callback)
    if not raw:
        return None
    return _parse_json_response(raw)


# ── Provider implementations ──────────────────────────────────────────────────


def _call_ollama(
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    temperature: float = DEFAULT_TEMPERATURE,
    timeout: float | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> str | None:
    def _do_call() -> str | None:
        if timeout is not None and timeout <= 0:
            return None
        if progress_callback:
            progress_callback(f"Contacting Ollama ({model})...")
        payload = json.dumps(
            {
                "model": model,
                "system": system,
                "prompt": user,
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": temperature},
            }
        ).encode()
        req = urllib.request.Request(
            OLLAMA_GENERATE_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(
            req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT
        ) as resp:
            data = json.loads(resp.read())
            pt = estimate_tokens(system + user)
            ct = estimate_tokens(data.get("response", ""))
            track(model, pt, ct)
            return data.get("response", "")

    return _retry_with_backoff(
        _do_call, 
        timeout_remaining=lambda: timeout,
        progress_callback=progress_callback
    )


def _call_openai_compat(
    api_key: str,
    base_url: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    temperature: float,
    timeout: float | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> str | None:
    def _do_call() -> str | None:
        if timeout is not None and timeout <= 0:
            return None
        if progress_callback:
            progress_callback(f"Contacting API ({model})...")
        payload = json.dumps(
            {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(
            req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT
        ) as resp:
            data = json.loads(resp.read())
            usage = data.get("usage", {})
            pt = usage.get("prompt_tokens", 0) or estimate_tokens(system + user)
            ct = usage.get("completion_tokens", 0) or estimate_tokens(
                data.get("choices", [{}])[0].get("message", {}).get("content", "")
            )
            track(model, pt, ct)
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    return _retry_with_backoff(
        _do_call, 
        timeout_remaining=lambda: timeout,
        progress_callback=progress_callback
    )


def _call_anthropic(
    api_key: str,
    base_url: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    timeout: float | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> str | None:
    def _do_call() -> str | None:
        if timeout is not None and timeout <= 0:
            return None
        if progress_callback:
            progress_callback(f"Contacting Anthropic ({model})...")
        payload = json.dumps(
            {
                "model": model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
        ).encode()
        headers = {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{base_url}/messages",
            data=payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(
            req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT
        ) as resp:
            data = json.loads(resp.read())
            usage = data.get("usage", {})
            pt = usage.get("input_tokens", 0) or estimate_tokens(system + user)
            ct = usage.get("output_tokens", 0) or estimate_tokens(
                data.get("content", [{}])[0].get("text", "")
            )
            track(model, pt, ct)
            return data.get("content", [{}])[0].get("text", "")

    return _retry_with_backoff(
        _do_call, 
        timeout_remaining=lambda: timeout,
        progress_callback=progress_callback
    )


# ── JSON parsing ──────────────────────────────────────────────────────────────

def _parse_json_response(text: str) -> dict | list | None:
    """Extract and parse JSON from AI response text."""
    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Extract from code block
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Find first JSON object or array
    for pattern in [r"\{.*\}", r"\[.*\]"]:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                continue

    return None
