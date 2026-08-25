"""
App Mapper — crawls a live deployed app and builds a structured map.

Uses urllib (no external deps) or Crawl4AI when available.
Returns structured map of pages, forms, links, and input fields.
"""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)
from patchi.core.constants import is_offline

_log = logging.getLogger("patchi.security.app_mapper")


class _LinkFormParser(HTMLParser):
    """Extract links and forms from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._in_form = False
        self._form_action = ""
        self._form_method = "GET"
        self._form_fields: list[dict] = []
        self._title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = {k: v or "" for k, v in attrs}

        if tag == "title":
            pass  # handled in data

        if tag == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                full = urljoin(self.base_url, href)
                self.links.append(full)

        if tag == "form":
            self._in_form = True
            self._form_action = urljoin(self.base_url, attr_dict.get("action", self.base_url))
            self._form_method = attr_dict.get("method", "GET").upper()
            self._form_fields = []

        if tag == "input" and self._in_form:
            self._form_fields.append(
                {
                    "name": attr_dict.get("name", ""),
                    "type": attr_dict.get("type", "text"),
                    "placeholder": attr_dict.get("placeholder", ""),
                }
            )

        if tag == "select" and self._in_form:
            self._form_fields.append(
                {
                    "name": attr_dict.get("name", ""),
                    "type": "select",
                    "placeholder": "",
                }
            )

        if tag == "textarea" and self._in_form:
            self._form_fields.append(
                {
                    "name": attr_dict.get("name", ""),
                    "type": "textarea",
                    "placeholder": "",
                }
            )

    def handle_endtag(self, tag: str):
        if tag == "form" and self._in_form:
            self._in_form = False
            self.forms.append(
                {
                    "action": self._form_action,
                    "method": self._form_method,
                    "fields": self._form_fields,
                }
            )

    def handle_data(self, data: str):
        pass


def patchi_map_app(url: str, max_pages: int = 20) -> dict:
    """Crawl a live app and return structured map."""
    if is_offline():
        return {"pages": [], "total_pages": 0, "total_entry_points": 0}
    visited: set[str] = set()
    pages: list[dict] = []
    queue = [url]

    while queue and len(pages) < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        try:
            req = urllib.request.Request(current, headers={"User-Agent": "Patchi-AppMapper/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    continue
                html = resp.read().decode("utf-8", errors="ignore")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            continue

        parser = _LinkFormParser(current)
        try:
            parser.feed(html)
        except Exception as e:
            _log.warning("patchi_map_app failed: %s", e)
            continue

        # Extract title
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ""

        pages.append(
            {
                "url": current,
                "title": title,
                "forms": parser.forms,
                "links": list(set(parser.links)),
            }
        )

        # Queue new links (same origin only)
        origin = urlparse(url).netloc
        for link in parser.links:
            if urlparse(link).netloc == origin and link not in visited:
                queue.append(link)

    total_entry_points = sum(len(p["forms"]) + len(p["links"]) for p in pages)

    return {
        "pages": pages,
        "total_pages": len(pages),
        "total_entry_points": total_entry_points,
    }


# ── App Mapper Agent ──────────────────────────────────────────────────────────


@register
class AppMapperAgent(BaseAgent):
    """Crawls live app and maps pages, forms, and entry points."""

    name = "AppMapperAgent"
    group = AgentGroup.SECURITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        app_url = (
            inp.brain.get("app_url", "")
            or inp.config.get("app_url", "")
            or inp.extra.get("app_url", "")
        )

        if not app_url:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_target_url",
                    severity=Severity.INFO,
                    file="",
                    message="No app URL configured — set 'app_url' in config to enable app mapping",
                )
            )
            return

        app_map = patchi_map_app(app_url)
        result.data["app_map"] = app_map
        result.data["total_pages"] = app_map["total_pages"]
        result.data["total_entry_points"] = app_map["total_entry_points"]

        # Flag forms without CSRF protection indicators
        for page in app_map["pages"]:
            for form in page["forms"]:
                if form["method"] == "POST":
                    field_names = [f["name"].lower() for f in form["fields"]]
                    if not any("csrf" in n or "token" in n or "_token" in n for n in field_names):
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="no_csrf_token",
                                severity=Severity.MEDIUM,
                                file=page["url"],
                                message=f"POST form at {form['action']} has no CSRF token field",
                                cwe="CWE-352",
                            )
                        )

        result.files_scanned = app_map["total_pages"]
