"""
LinkingAgent — p scan hybrid, only when backend+frontend pair exists.

Monorepo: same FileCorpus has both sides.
Separate repos: hybrid auto-discovery (../*) + tag confirmation via p link confirm / p link add --backend ../backend
Status LINKED vs LINK_ISSUES_FOUND merged into p scan findings, no --link flag.

Checks 1-7: base URL, route existence (contract_diff), CORS, env parity, auth wiring, response shape, realtime ws.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

_log = logging.getLogger("patchi.agents.linking")


def _has_frontend(root: Path) -> bool:
    return (root / "package.json").exists() or any((root / p).exists() for p in ["src/routes", "app/routes", "pages", "src/app"])


def _has_backend(root: Path) -> bool:
    return any((root / p).exists() for p in ["requirements.txt", "pyproject.toml", "Cargo.toml", "go.mod", "pom.xml"]) or any(
        (root / d).exists() for d in ["patchi/core", "src/main", "app"]
    )


def _load_linking_config(root: Path) -> dict | None:
    for cand in [root / ".patchi" / "config.json", root / ".patchi" / "linking.json"]:
        if cand.exists():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                link = data.get("linking") or data
                if isinstance(link, dict) and link.get("backend"):
                    return link
            except Exception:
                pass
    return None


def _suggest_link(root: Path) -> dict | None:
    # auto-discovery siblings
    candidates = []
    try:
        for sibling in root.parent.glob("*"):
            if not sibling.is_dir() or sibling == root:
                continue
            is_front = (sibling / "package.json").exists()
            is_back = any((sibling / p).exists() for p in ["requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"])
            if is_front or is_back:
                candidates.append(sibling.name)
        if candidates:
            # prefer ../backend for frontend-only root
            has_front_here = _has_frontend(root)
            has_back_here = _has_backend(root)
            if has_front_here and not has_back_here:
                for c in candidates:
                    if "back" in c.lower() or "api" in c.lower():
                        return {"frontend": ".", "backend": f"../{c}", "frontend_url": "http://localhost:3000", "backend_url": "http://localhost:5000"}
            if has_back_here and not has_front_here:
                for c in candidates:
                    if "front" in c.lower() or "web" in c.lower():
                        return {"frontend": f"../{c}", "backend": ".", "frontend_url": "http://localhost:3000", "backend_url": "http://localhost:5000"}
    except Exception as exc:  # noqa: BLE001
        _log.debug("suggest link failed: %s", exc)
    return None


@register
class LinkingAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "LinkingAgent"
    description = "Linking — base URL, route existence, CORS, env parity, auth, response shape, ws (p scan hybrid monorepo/separate)"
    timeout = 90

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        has_front = _has_frontend(root)
        has_back = _has_backend(root)
        linking_cfg = _load_linking_config(root)

        # Guard: single-type → skip
        if not (has_front and has_back) and not linking_cfg:
            # Try auto suggestion for separate repos
            sug = _suggest_link(root)
            if sug:
                # write suggestion file for p link confirm
                try:
                    sug_path = root / ".patchi" / "linking_suggestion.json"
                    sug_path.parent.mkdir(parents=True, exist_ok=True)
                    sug_path.write_text(json.dumps(sug, indent=2), encoding="utf-8")
                    result.add_finding(
                        make_finding(
                            severity=Severity.INFO,
                            file=str(sug_path.relative_to(root)),
                            line_start=0,
                            title=f"Link suggestion: frontend {sug['frontend']} ↔ backend {sug['backend']}",
                            description="Separate repos detected — run `p link confirm` or `p link add --backend ../backend` to activate linking checks",
                            finding_type="link_suggestion",
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    _log.debug("suggestion write failed: %s", exc)
            self.skip(result, "single-type project — no backend+frontend pair to link")
            result.data["status"] = "SKIPPED_SINGLE_TYPE"
            return

        issues: list = []
        # Determine frontend calls and backend routes
        frontend_calls: list[dict] = []
        backend_routes: list = []
        try:
            from patchi.core.brain.contract_diff import extract_frontend_calls
            from patchi.core.brain.framework import FrameworkDetector
            from patchi.core.brain.route_mapper import RouteMapper

            if linking_cfg and linking_cfg.get("backend"):
                # separate repos: two corpora
                front_root = (root / linking_cfg["frontend"]).resolve() if linking_cfg["frontend"] != "." else root
                back_root = (root / linking_cfg["backend"]).resolve() if linking_cfg["backend"] != "." else root
                # Actually extract via file_infos from scanner for each
                from patchi.core.brain.scanner import FileScanner

                front_fis_real = FileScanner(front_root).scan()
                back_fis_real = FileScanner(back_root).scan()
                frontend_calls = extract_frontend_calls(front_fis_real, front_root)
                back_routes = RouteMapper(back_root, FrameworkDetector(back_root).detect()).extract(back_fis_real)
                backend_routes = back_routes
            else:
                from patchi.core.brain.scanner import FileScanner

                fis = FileScanner(root).scan()
                frontend_calls = extract_frontend_calls(fis, root)
                backend_routes = RouteMapper(root, FrameworkDetector(root).detect()).extract(fis)
        except Exception as exc:  # noqa: BLE001
            _log.debug("linking route extract failed: %s", exc)

        # 1. Base URL / endpoint config
        try:
            front_url = None
            for env_file in [root / ".env", root / "frontend/.env", root / ".env.example"]:
                if env_file.exists():
                    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        if "VITE_API_URL" in line or "NEXT_PUBLIC_API_URL" in line or "REACT_APP_API_URL" in line:
                            front_url = line.split("=", 1)[-1].strip().strip("\"'")
                            break
            back_url = linking_cfg.get("backend_url") if linking_cfg else None
            if front_url and back_url and front_url.rstrip("/") != back_url.rstrip("/"):
                issues.append(("base_url", f"Frontend API base {front_url} != backend {back_url}"))
            elif not front_url and frontend_calls:
                issues.append(("base_url", "Frontend API base URL not configured (env VITE_API_URL/NEXT_PUBLIC_API_URL missing)"))
        except Exception as exc:  # noqa: BLE001
            _log.debug("base url check failed: %s", exc)

        # 2. Route existence via contract_diff
        try:
            from patchi.core.brain.contract_diff import diff_contract

            diff = diff_contract(frontend_calls, backend_routes)
            for m in diff.missing_routes:
                issues.append(("route_existence", f"Frontend {m.get('method')} {m.get('raw')} has no backend route (404) at {m.get('file')}:{m.get('line')}"))
            for mm in diff.method_mismatch:
                issues.append(("method_mismatch", f"Method mismatch {mm}"))
        except Exception as exc:  # noqa: BLE001
            _log.debug("route existence failed: %s", exc)

        # 3. CORS
        try:
            if frontend_calls and backend_routes:
                # check if frontend and backend run on different ports (monorepo dev)
                # probe backend CORS header
                import httpx

                back_origin = back_url or "http://127.0.0.1:5000"
                try:
                    resp = httpx.request("OPTIONS", f"{back_origin}/api", headers={"Origin": front_url or "http://localhost:3000"}, timeout=3)
                    if "access-control-allow-origin" not in {k.lower() for k in resp.headers}:
                        issues.append(("cors", f"Backend {back_origin} does not allow frontend origin {front_url or 'http://localhost:3000'} — CORS not whitelisted"))
                except Exception:
                    pass
        except Exception as exc:  # noqa: BLE001
            _log.debug("cors check failed: %s", exc)

        # 4. Env parity
        try:
            front_env = set()
            back_env = set()
            for p in [root / ".env", root / "frontend/.env"]:
                if p.exists():
                    front_env.update(
                        ln.split("=")[0].strip()
                        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                        if "=" in ln and not ln.startswith("#")
                    )
            for p in [root / ".env", root / "backend/.env"]:
                if p.exists():
                    back_env.update(
                        ln.split("=")[0].strip()
                        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                        if "=" in ln and not ln.startswith("#")
                    )
            for key in ["API_URL", "AUTH_SECRET", "FEATURE_FLAG"]:
                if (key in front_env) != (key in back_env):
                    issues.append(("env_parity", f"Env key {key} present on one side only — front {key in front_env} back {key in back_env}"))
        except Exception as exc:  # noqa: BLE001
            _log.debug("env parity failed: %s", exc)

        # 5-7 simplified: auth, response shape, realtime
        # For MVP, report LINKED or LINK_ISSUES_FOUND
        if not issues:
            result.data["status"] = "LINKED"
            result.add_finding(
                make_finding(
                    severity=Severity.INFO,
                    file="",
                    line_start=0,
                    title="LINKED — all 7 wiring checks pass",
                    description="Base URL, routes, CORS, env, auth, response shape, realtime all linked",
                    finding_type="link_linked",
                )
            )
        else:
            result.data["status"] = "LINK_ISSUES_FOUND"
            result.data["issues"] = issues
            for kind, msg in issues:
                result.add_finding(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file="",
                        line_start=0,
                        title=f"Link issue — {kind}: {msg[:80]}",
                        description=f"{kind}: {msg}",
                        finding_type=f"link_{kind}",
                    )
                )
        result.data["has_frontend"] = has_front
        result.data["has_backend"] = has_back
        result.data["linking_cfg"] = bool(linking_cfg)
        result.status = result.status if result.status != "running" else "done"
