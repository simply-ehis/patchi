"""
Unified AI client for Patchi agents.

Supports:
  - System message + user message (two-role prompting)
  - Local Ollama, OpenAI-compatible APIs, Anthropic
  - Structured JSON output (with fallback parsing)
  - Automatic key rotation across configured providers
  - Offline fallback (returns None, never crashes)
"""

from __future__ import annotations

import json

# ── Public API ─────────────────────────────────────────────────────────────────
import logging
import os
import re
import time
import urllib.request

from loguru import logger

from patchi.core.ai.cost_tracker import estimate_tokens, track
from patchi.core.constants import (
    AI_HORDE_ANON_KEY,
    AI_HORDE_BASE_URL,
    AI_HORDE_MAX_POLL_RETRIES,
    AI_HORDE_MAX_TOKENS,
    AI_HORDE_POLL_INTERVAL_SEC,
    ANTHROPIC_API_VERSION,
    DEFAULT_MAX_TOKENS,
    DEFAULT_TEMPERATURE,
    HTTP_REQUEST_TIMEOUT,
    HTTP_REQUEST_TIMEOUT_SHORT,
    OLLAMA_GENERATE_URL,
    PROVIDERS,
)

_log = logging.getLogger("patchi.core.client")

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
) -> str | None:
    """
    Send a system+user prompt to the configured AI.
    Returns the response text, or None if no AI is available / call fails.

    Priority: local Ollama → configured API keys → AI Horde fallback → None.

    Honors PATCHI_OFFLINE=1 (set by `p scan --offline`): returns None without
    making ANY network call — the flag's documented "static analysis only, zero
    token cost" contract.

    `timeout` bounds the ENTIRE call (all providers tried, poll loops included),
    so a hung provider can never freeze a scan or leave a worker thread alive
    indefinitely. None = no overall deadline (per-request socket timeouts only).
    """
    if os.environ.get("PATCHI_OFFLINE"):
        return None

    deadline = time.monotonic() + timeout if timeout is not None else None

    def _remaining() -> float | None:
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())

    _ensure_env_loaded()
    ai_config = config.get("ai", {})

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
    except Exception:
        pass  # fall through to default routing

    # Try local Ollama first
    local_model = ai_config.get("local_model_name")
    if local_model:
        result = _call_ollama(local_model, system_prompt, user_prompt, max_tokens, temperature, _remaining())
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
                api_key, base_url, model, system_prompt, user_prompt, max_tokens, _remaining()
            )
        else:
            result = _call_openai_compat(
                api_key, base_url, model, system_prompt, user_prompt, max_tokens, temperature, _remaining()
            )

        if result:
            logger.debug(f"AI call succeeded via {key_cfg.get('name', 'unknown')} ({model})")
            return result

    # Free fallback — pollinations.ai (keyless, unlimited)
    poll = PROVIDERS.get("pollinations", {})
    poll_url = poll.get("base_url", "https://text.pollinations.ai/openai")
    poll_model = poll.get("model", "openai")
    result = _call_openai_compat(
        "", poll_url, poll_model, system_prompt, user_prompt, max_tokens, temperature, _remaining()
    )
    if result:
        return result

    # Last resort — AI Horde community endpoint (free, keyless, always available)
    if ai_config.get("horde_fallback"):
        horde_key = ai_config.get("horde_key", AI_HORDE_ANON_KEY)
        return _call_ai_horde(horde_key, f"{system_prompt}\n\n{user_prompt}", max_tokens, _remaining())

    return None


def call_ai_structured(
    config: dict,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = 0.2,
) -> dict | list | None:
    """
    Call AI and parse the response as JSON.
    Returns parsed JSON or None.
    """
    raw = call_ai(config, system_prompt, user_prompt, max_tokens, temperature)
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
) -> str | None:
    try:
        if timeout is not None and timeout <= 0:
            return None
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
        with urllib.request.urlopen(req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
            pt = estimate_tokens(system + user)
            ct = estimate_tokens(data.get("response", ""))
            track(model, pt, ct)
            return data.get("response", "")
    except Exception as e:
        logger.debug(f"Ollama call failed: {e}")
        return None


def _call_openai_compat(
    api_key: str,
    base_url: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    temperature: float,
    timeout: float | None = None,
) -> str | None:
    try:
        if timeout is not None and timeout <= 0:
            return None
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
        with urllib.request.urlopen(req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
            usage = data.get("usage", {})
            pt = usage.get("prompt_tokens", 0) or estimate_tokens(system + user)
            ct = usage.get("completion_tokens", 0) or estimate_tokens(
                data.get("choices", [{}])[0].get("message", {}).get("content", "")
            )
            track(model, pt, ct)
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        logger.debug(f"OpenAI-compat call failed ({model}): {e}")
        return None


def _call_anthropic(
    api_key: str,
    base_url: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    timeout: float | None = None,
) -> str | None:
    try:
        if timeout is not None and timeout <= 0:
            return None
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
        with urllib.request.urlopen(req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
            usage = data.get("usage", {})
            pt = usage.get("input_tokens", 0) or estimate_tokens(system + user)
            ct = usage.get("output_tokens", 0) or estimate_tokens(
                data.get("content", [{}])[0].get("text", "")
            )
            track(model, pt, ct)
            return data.get("content", [{}])[0].get("text", "")
    except Exception as e:
        logger.debug(f"Anthropic call failed: {e}")
        return None


def _call_ai_horde(
    api_key: str,
    prompt: str,
    max_tokens: int,
    timeout: float | None = None,
) -> str | None:
    """
    AI Horde community endpoint — always available, no account required.
    Uses the anonymous key by default.
    Slower than dedicated keys but always reachable.
    """
    try:
        if timeout is not None and timeout <= 0:
            return None
        deadline = time.monotonic() + timeout if timeout is not None else None
        payload = json.dumps(
            {
                "prompt": prompt,
                "params": {
                    "max_length": min(max_tokens, AI_HORDE_MAX_TOKENS),
                    "temperature": DEFAULT_TEMPERATURE,
                },
                "models": ["mistralai/Mistral-7B-Instruct-v0.2"],
                "trusted_workers": False,
            }
        ).encode()
        req = urllib.request.Request(
            f"{AI_HORDE_BASE_URL}/generate/text/async",
            data=payload,
            headers={"apikey": api_key, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT_SHORT) as resp:
            data = json.loads(resp.read())
            job_id = data.get("id")
        if not job_id:
            return None
        for _ in range(AI_HORDE_MAX_POLL_RETRIES):
            if deadline is not None and time.monotonic() >= deadline:
                return None
            time.sleep(AI_HORDE_POLL_INTERVAL_SEC)
            if deadline is not None and time.monotonic() >= deadline:
                return None
            status_req = urllib.request.Request(
                f"{AI_HORDE_BASE_URL}/generate/text/status/{job_id}",
                headers={"apikey": api_key},
            )
            with urllib.request.urlopen(status_req, timeout=timeout if timeout is not None else HTTP_REQUEST_TIMEOUT_SHORT) as resp:
                status = json.loads(resp.read())
            if status.get("done"):
                generations = status.get("generations", [])
                if generations:
                    text = generations[0].get("text", "").strip()
                    ct = estimate_tokens(text)
                    track("mistralai/Mistral-7B-Instruct-v0.2", estimate_tokens(prompt), ct)
                    return text
                return None
        return None
    except Exception as e:
        _log.warning("_call_ai_horde failed: %s", e)
        return None


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
