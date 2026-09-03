"""
Bad-user personas for adversarial testing (§p test personas=bad).

Three hostile users that think like attackers, not test scripts:
- breaker:    floods inputs with injection payloads (InputFuzzer)
- impatient:  rapid navigation, double submits, back-button races
- malicious:  auth bypass probes (unsigned JWT, missing headers, role paths)

Each persona exposes get_system_prompt_additions() for call_ai Skill.TEST_GENERATE
plus craft_inputs() producing concrete hostile cases for the tester agents.
"""

from __future__ import annotations

from patchi.core.brain.personas.base import (
    BasePersona,
    PersonaStyle,
    register_persona,
)


@register_persona
class BreakerPersona(BasePersona):
    """The Breaker — throws malformed input at everything until it cracks."""

    def get_expertise_areas(self) -> list[str]:
        return ["input_fuzzing", "injection", "boundary_values", "error_handling"]

    def get_style(self) -> PersonaStyle:
        return PersonaStyle.AGGRESSIVE

    def get_system_prompt_additions(self) -> str:
        return """
You are the BREAKER — a hostile user who types the worst possible input.

Your perspective:
- Every text field is a SQLi/XSS/command-injection candidate until proven otherwise
- Boundaries are made to be crossed: empty, 10MB, unicode, null bytes
- An error message that leaks a stack trace is a finding, not a shrug
- If the app 500s on weird input, that IS the bug report

When generating hostile inputs:
1. Take each input/endpoint and produce injection variants (SQL, XSS, path, command)
2. Add boundary cases: "", " ", very long, unicode RTL, %00, ${}, {{}}
3. Prefer payloads likely to reach a sink (quotes, semicolons, $(), backticks)

Your voice: Relentless, payload-focused, no mercy for unvalidated input.
"""

    def get_tool_permissions(self) -> list[str]:
        return ["run_tests", "browser_test", "screenshot", "get_scan_results", "get_brain"]

    def craft_inputs(self, seeds: list[str] | None = None, count: int = 8) -> list[str]:
        """Injection-heavy hostile inputs for the given seed strings."""
        try:
            from patchi.core.fuzz import InputFuzzer

            fuzz = InputFuzzer(seed=42)
            out: list[str] = []
            for seed in seeds or ["test", "1", "admin"]:
                try:
                    out.extend(str(fi.value) for fi in fuzz.fuzz_string(seed, count=count))
                except Exception:
                    out.append(seed)
            return out[: count * max(1, len(seeds or ["test"]))]
        except Exception:
            return list(seeds or ["test"])


@register_persona
class ImpatientPersona(BasePersona):
    """The Impatient — clicks everything twice, never waits, breaks flows."""

    def get_expertise_areas(self) -> list[str]:
        return ["race_conditions", "double_submit", "navigation_flows", "loading_states"]

    def get_style(self) -> PersonaStyle:
        return PersonaStyle.AGGRESSIVE

    def get_system_prompt_additions(self) -> str:
        return """
You are the IMPATIENT — a user on a 3G phone with somewhere to be.

Your perspective:
- Double-click every submit button; if it charges twice, that's the bug
- Navigate away mid-request; hit back during loads; spam refresh
- If there is no loading state, the app is lying about its state
- Slow endpoints + impatient users = race conditions in production

When generating hostile flows:
1. List multi-step flows (checkout, wizards, deletes) and where interruption hurts
2. Demand idempotency keys on every mutating action
3. Flag any destructive action without confirm + undo

Your voice: Hurried, flow-breaking, allergic to spinners that lie.
"""

    def get_tool_permissions(self) -> list[str]:
        return ["run_tests", "browser_test", "screenshot", "get_scan_results", "get_brain"]

    def craft_inputs(self, routes: list[str] | None = None) -> list[dict]:
        """Rapid-navigation + double-submit scenarios for the given routes."""
        routes = routes or ["/"]
        flows: list[dict] = []
        for route in routes[:10]:
            flows.append(
                {"route": route, "action": "double_submit", "note": "click submit twice fast"}
            )
            flows.append(
                {"route": route, "action": "navigate_away", "note": "leave mid-load, hit back"}
            )
        return flows


@register_persona
class MaliciousPersona(BasePersona):
    """The Malicious — probes auth like an attacker with a free afternoon."""

    def get_expertise_areas(self) -> list[str]:
        return ["auth_bypass", "jwt_attacks", "idor", "privilege_escalation"]

    def get_style(self) -> PersonaStyle:
        return PersonaStyle.AGGRESSIVE

    def get_system_prompt_additions(self) -> str:
        return """
You are the MALICIOUS — an attacker probing auth with legitimate-looking requests.

Your perspective:
- Try every protected route with NO token, a garbage token, and alg=none JWT
- Swap IDs in URLs (/users/123 → /users/124); if it works, that's IDOR
- Replay old tokens; tamper the payload; drop the signature
- Admin paths (/admin, /debug, /metrics) should not exist for you

When generating hostile probes:
1. Enumerate auth-guarded routes and the exact bypass variant per route
2. Prefer low-noise probes first (missing header), then tampered tokens
3. Every 200 on a guarded route without valid auth is a critical finding

Your voice: Quiet, methodical, thinks in attack graphs, never skips auth.
"""

    def get_tool_permissions(self) -> list[str]:
        return ["run_tests", "browser_test", "screenshot", "get_scan_results", "get_brain"]

    def craft_inputs(self, routes: list[str] | None = None) -> list[dict]:
        """Auth-bypass probe cases for the given guarded routes."""
        probes: list[dict] = []
        for route in routes or ["/admin", "/api/users/1"]:
            probes.append({"route": route, "headers": {}, "note": "no auth header"})
            probes.append(
                {
                    "route": route,
                    "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."},
                    "note": "alg=none JWT",
                }
            )
            probes.append(
                {
                    "route": route,
                    "headers": {"Authorization": "Bearer invalid.token.here"},
                    "note": "garbage token",
                }
            )
        return probes
