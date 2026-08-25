"""
Patchi Domain Activator
=======================

Determines which security domains should be activated for a given codebase
based on detected imports, dependencies, file extensions, infra files, and
other signals. Each domain has a dedicated ``_check_<domain_id>`` function
that returns ``True`` if the domain should be activated.

The functions are registered in ``_DOMAIN_CHECKERS`` and invoked by the
scanner with an 11-element tuple (see ``_DomainContext`` below).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Context passed to every checker
# ---------------------------------------------------------------------------
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

_log = logging.getLogger("patchi.brain.domain_activator")

@dataclass(frozen=True)
class _DomainContext:
    """Structured view of the 11-element args tuple passed by the scanner.

    Fields (in order):
        language:       detected primary language (e.g. "python", "go")
        framework:      detected framework name (e.g. "django", "rails")
        imports:        list of import strings observed in source files
        deps:           list of declared dependencies (gemfile, package.json, etc.)
        routes:         list of route strings detected (URL paths, handlers)
        config_keys:    list of config keys observed in YAML/ENV/toml files
        infra_files:    list of infra-relative file paths (Cargo.toml, routes.rb, etc.)
        has_web:        True if a web framework is detected
        has_cli:        True if a CLI entrypoint is detected
        has_mobile:     True if mobile (iOS/Android) markers are present
        exts:           list of file extensions observed (lowercase, with leading dot)
    """

    language: str
    framework: str
    imports: Sequence[str]
    deps: Sequence[str]
    routes: Sequence[str]
    config_keys: Sequence[str]
    infra_files: Sequence[str]
    has_web: bool
    has_cli: bool
    has_mobile: bool
    exts: Sequence[str]

    @classmethod
    def from_args(cls, args: Sequence) -> "_DomainContext":
        if len(args) != 11:
            raise ValueError(
                f"Expected 11-element args tuple, got {len(args)}: {args!r}"
            )
        (
            language,
            framework,
            imports,
            deps,
            routes,
            config_keys,
            infra_files,
            has_web,
            has_cli,
            has_mobile,
            exts,
        ) = args
        return cls(
            language=language or "",
            framework=framework or "",
            imports=tuple(imports or ()),
            deps=tuple(deps or ()),
            routes=tuple(routes or ()),
            config_keys=tuple(config_keys or ()),
            infra_files=tuple(infra_files or ()),
            has_web=bool(has_web),
            has_cli=bool(has_cli),
            has_mobile=bool(has_mobile),
            exts=tuple(exts or ()),
        )


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _compile_pattern(pat: str) -> re.Pattern:
    """Compile a substring pattern into a regex with word-boundary awareness.

    For patterns that begin or end with a word character (letter, digit, or
    underscore), we add a negative lookbehind / lookahead so that the pattern
    must NOT be preceded/followed by another word character. This prevents
    false positives like the pattern ``"sync"`` matching the Python import
    ``"asyncio"`` (which contains "sync" as a substring) while still matching
    legitimate occurrences like ``"sync.Mutex"``, ``"use sync"``, etc.

    For patterns that begin or end with a non-word character (e.g. ``"libc::"``,
    ``"<stdlib.h>"``, ``"@sveltejs/kit"``), no boundary assertion is added on
    that side because the non-word character itself acts as a sufficient
    delimiter.
    """
    escaped = re.escape(pat)
    if pat and (pat[0].isalnum() or pat[0] == "_"):
        escaped = r"(?<![A-Za-z0-9_])" + escaped
    if pat and (pat[-1].isalnum() or pat[-1] == "_"):
        escaped = escaped + r"(?![A-Za-z0-9_])"
    return re.compile(escaped, re.IGNORECASE)


def _has_import(imports: Iterable[str], patterns: Iterable[str]) -> bool:
    """Return True if any ``patterns`` substring is found in any ``imports`` entry.

    Uses word-boundary-aware matching (see :func:`_compile_pattern`) so that
    short identifiers like ``"sync"`` or ``"context"`` do not match inside
    longer identifiers like ``"asyncio"`` or ``"user_context_manager"``.
    """
    compiled = [_compile_pattern(p) for p in patterns]
    for imp in imports:
        for r in compiled:
            if r.search(imp):
                return True
    return False


def _has_dependency(deps: Iterable[str], patterns: Iterable[str]) -> bool:
    """Return True if any ``patterns`` substring is found in any ``deps`` entry.

    Same word-boundary semantics as :func:`_has_import`. This prevents e.g.
    a pattern ``"rails"`` from matching a dep named ``"grails"``.
    """
    compiled = [_compile_pattern(p) for p in patterns]
    for dep in deps:
        for r in compiled:
            if r.search(dep):
                return True
    return False


def _has_ext(exts: Iterable[str], patterns: Iterable[str]) -> bool:
    """Return True if any ``patterns`` extension is observed.

    Patterns are matched as case-insensitive suffix so that ``".go"`` matches
    both ``".go"`` and ``".GO"`` (rare, but legacy Windows tooling produces it).
    """
    exts_lower = [e.lower() for e in exts]
    return any(
        ext.lower().endswith(pat.lower()) for pat in patterns for ext in exts_lower
    )


def _has_infra_file(infra_files: Iterable[str], patterns: Iterable[str]) -> bool:
    """Return True if any infra file path matches any pattern (case-insensitive)."""
    infra_lower = [f.lower() for f in infra_files]
    return any(
        pat.lower() in f for pat in patterns for f in infra_lower
    )


def _has_config_key(config_keys: Iterable[str], patterns: Iterable[str]) -> bool:
    """Return True if any config key matches any pattern (case-insensitive)."""
    keys_lower = [k.lower() for k in config_keys]
    return any(
        pat.lower() in k for pat in patterns for k in keys_lower
    )


# ---------------------------------------------------------------------------
# Domain checkers
# ---------------------------------------------------------------------------

def _check_native_code_safety(*args) -> bool:
    """Activate for C/C++/Rust codebases with native-unsafe patterns."""
    ctx = _DomainContext.from_args(args)

    ncs_exts = [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".rs"]
    ncs_imports = [
        "unsafe",                       # Rust unsafe blocks (lexically detectable)
        "std::ptr",                     # Rust raw pointer module
        "std::mem::transmute",          # Rust transmute
        "libc::",                       # Rust libc FFI
        "extern \"C\"",                 # Rust FFI
        "Box::into_raw",                # Rust manual lifetime
        "Box::from_raw",
        "<stdlib.h>",                   # C/C++ malloc family
        "<string.h>",                   # C/C++ strcpy family
        "<stdio.h>",                    # C/C++ printf family
        "strcpy", "strcat", "sprintf", "gets",  # CWE-119 classics
    ]
    ncs_deps: list[str] = []  # C/C++/Rust do not use dep manifests we scan here

    return (
        _has_ext(ctx.exts, ncs_exts)
        or _has_import(ctx.imports, ncs_imports)
        or _has_dependency(ctx.deps, ncs_deps)
    )


def _check_go_concurrency(*args) -> bool:
    """Activate for Go codebases with goroutine / sync usage."""
    ctx = _DomainContext.from_args(args)

    gco_exts = [".go"]
    gco_imports = [
        "go func",                      # goroutine spawn (lexical)
        "sync",                         # sync.Mutex / sync.RWMutex / sync.WaitGroup
        "sync/atomic",                  # atomic primitives
        "context",                      # context.Context for cancellation
        "sync.Map",                     # concurrent map
        "errgroup",                     # golang.org/x/sync/errgroup
        "runtime.Goexit",              # goroutine exit
    ]
    gco_deps = [
        "golang.org/x/sync",            # errgroup, semaphore
        "github.com/sourcegraph/conc",  # modern concurrency helpers
    ]

    return (
        _has_ext(ctx.exts, gco_exts)
        or _has_import(ctx.imports, gco_imports)
        or _has_dependency(ctx.deps, gco_deps)
    )


def _check_jvm_hardening(*args) -> bool:
    """Activate for JVM (Java/Kotlin/Scala) codebases, esp. Spring Boot."""
    ctx = _DomainContext.from_args(args)

    jvm_exts = [".java", ".kt", ".kts", ".scala"]
    jvm_imports = [
        "org.springframework",          # Spring Framework
        "org.springframework.boot",     # Spring Boot
        "javax.servlet",                # Servlet API
        "jakarta.servlet",              # Jakarta EE (Spring Boot 3+)
        "java.io.ObjectInputStream",    # CWE-502 deserialization
        "java.lang.Runtime",            # CWE-78 command exec
        "java.lang.reflect",            # CWE-470 reflection
        "com.fasterxml.jackson",        # Jackson (default typing risk)
        "com.alibaba.fastjson",         # Fastjson (autoType risk)
        "org.apache.commons.collections",  # ysoserial gadget
    ]
    jvm_deps = [
        "spring-boot-starter",
        "spring-boot-actuator",         # CWE-526 actuator exposure
        "spring-boot-devtools",         # CWE-489 debug code
        "spring-web",
        "spring-webmvc",
        "spring-webflux",
        "javax.servlet:javax.servlet-api",
        "jakarta.servlet:jakarta.servlet-api",
        "org.apache.commons:commons-collections",
    ]

    jvm_infra = ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"]

    return (
        _has_ext(ctx.exts, jvm_exts)
        or _has_import(ctx.imports, jvm_imports)
        or _has_dependency(ctx.deps, jvm_deps)
        or _has_infra_file(ctx.infra_files, jvm_infra)
    )


def _check_mobile_native(*args) -> bool:
    """Activate for iOS (Swift) / Android (Kotlin/Java) mobile codebases."""
    ctx = _DomainContext.from_args(args)

    mob_exts = [".swift", ".kt", ".kts", ".m", ".mm"]
    mob_imports = [
        "UIKit",                        # iOS UI framework
        "SwiftUI",                      # iOS modern UI
        "Foundation",                   # iOS core (often co-located)
        "Security",                     # iOS Keychain
        "androidx.",                    # AndroidX
        "android.app",                  # Android app framework
        "android.content",              # Android Intent / Context
        "android.security.keystore",    # Android Keystore
        "com.android",                  # Android tooling
        "java.security.KeyStore",       # Java/Android Keystore
    ]
    mob_deps = [
        "com.android.tools.build:gradle",       # Android Gradle plugin
        "io.realm:realm",                       # Realm mobile DB
        "androidx.compose",                     # Jetpack Compose
        "io.coil-kt:coil",                      # Coil (Android image lib)
        "com.google.firebase",                  # Firebase mobile SDK
        "platform-ui",                          # iOS package alias
    ]
    mob_infra = [
        "info.plist",
        "androidmanifest.xml",
        "project.pbxproj",
        "package.swift",
        "podfile",
        "podfile.lock",
        "build.gradle",
        "build.gradle.kts",
    ]

    return (
        _has_ext(ctx.exts, mob_exts)
        or _has_import(ctx.imports, mob_imports)
        or _has_dependency(ctx.deps, mob_deps)
        or _has_infra_file(ctx.infra_files, mob_infra)
        or ctx.has_mobile
    )


def _check_ruby_rails(*args) -> bool:
    """Activate for Ruby on Rails codebases."""
    ctx = _DomainContext.from_args(args)

    rrs_exts = [".rb", ".erb", ".rhtml", ".rjs", ".rake", ".gemspec"]
    rrs_imports = [
        "ActiveRecord",                 # ORM
        "ActionController",             # controllers
        "ActionView",                   # views
        "ActionDispatch",               # routing
        "Rails",                        # Rails constant
        "ApplicationController",
        "ApplicationRecord",
        "ActiveModel",
        "ActiveJob",
        "ActiveSupport",
        "protect_from_forgery",         # CSRF config
        "params.permit",                # strong params
        "attr_accessible",              # legacy mass-assignment
    ]
    rrs_deps = [
        "rails",                        # the framework
        "activerecord",
        "actionpack",
        "activesupport",
        "actionview",
        "railties",
        "pg",                           # Postgres adapter (often Rails)
        "mysql2",
        "puma",                         # Rails app server
        "devise",                       # Rails auth
    ]
    rrs_infra = [
        "config/routes.rb",
        "config/application.rb",
        "config/database.yml",
        "gemfile",
        "gemfile.lock",
        "config.ru",
        "bin/rails",
        "rakefile",
    ]

    return (
        _has_ext(ctx.exts, rrs_exts)
        or _has_import(ctx.imports, rrs_imports)
        or _has_dependency(ctx.deps, rrs_deps)
        or _has_infra_file(ctx.infra_files, rrs_infra)
    )


def _check_svelte_ssr(*args) -> bool:
    """Activate for SvelteKit SSR codebases."""
    ctx = _DomainContext.from_args(args)

    ssr_exts = [".svelte", ".svelte.js", ".svelte.ts"]
    ssr_imports = [
        "@sveltejs/kit",                # SvelteKit core
        "$app/store",                   # SvelteKit $app module
        "$app/environment",
        "$app/navigation",
        "$env/static/private",          # private env (server-only)
        "$env/dynamic/private",
        "$env/static/public",
        "$env/dynamic/public",
        "$lib/server",                  # server-only lib
        "import { redirect }",          # SvelteKit redirect helper
        "import { error }",             # SvelteKit error helper
        "cookies.set",                  # SvelteKit cookies API (called inside actions/load)
        "cookies.get",                  # SvelteKit cookies API (read)
    ]
    ssr_deps = [
        "@sveltejs/kit",
        "@sveltejs/adapter-node",
        "@sveltejs/adapter-auto",
        "@sveltejs/vite-plugin-svelte",
        "svelte",
    ]
    ssr_infra = [
        "svelte.config.js",
        "svelte.config.mjs",
        "src/routes/+page.server.js",
        "src/routes/+page.server.ts",
        "src/routes/+layout.server.js",
        "src/routes/+layout.server.ts",
        "+page.server.js",
        "+page.server.ts",
        "+layout.server.js",
        "+layout.server.ts",
        "src/app.html",
    ]

    return (
        _has_ext(ctx.exts, ssr_exts)
        or _has_import(ctx.imports, ssr_imports)
        or _has_dependency(ctx.deps, ssr_deps)
        or _has_infra_file(ctx.infra_files, ssr_infra)
    )


def _check_cargo_supply_chain(*args) -> bool:
    """Activate for Rust codebases that declare any Cargo dependencies."""
    ctx = _DomainContext.from_args(args)


    csc_infra = [
        "cargo.toml",                   # case-insensitive
        "cargo.lock",
    ]

    # Activation requires Cargo.toml present AND a non-empty [dependencies] section.
    # The scanner surfaces Cargo.toml as an infra_file; we trust its presence.
    if not (
        _has_infra_file(ctx.infra_files, csc_infra)
        or _has_ext(ctx.exts, [".rs"])
        or _has_dependency(ctx.deps, ["cargo"])  # rare: cargo as a Cargo plugin
    ):
        return False

    # At least one Rust source file OR Cargo.toml presence is required.
    # The deps list may include crates pulled from Cargo.toml; if non-empty,
    # the project has dependencies to audit.
    if ctx.deps:
        return True

    # Fallback: just Cargo.toml presence (we cannot verify dep count from here,
    # but the scanner's domain runner will re-check the file's [dependencies] section).
    return _has_infra_file(ctx.infra_files, csc_infra)


def _check_nodejs_runtime(*args) -> bool:
    """Activate for Node.js codebases (JS/TS) using Node runtime APIs."""
    ctx = _DomainContext.from_args(args)

    njs_exts = [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]
    njs_imports = [
        "require(",                     # CommonJS require
        "child_process",                # CWE-78 command exec
        "node:child_process",
        "eval(",                        # CWE-95 code injection
        "new Function(",                # CWE-95 dynamic function
        "vm.runInNewContext",           # CWE-95 vm sandbox (not a security boundary)
        "vm.runInThisContext",
        "node:vm",
        "fs.readFile",                  # CWE-22 path traversal (fs family)
        "fs.writeFile",
        "fs.createReadStream",
        "fs.createWriteStream",
        "path.join",                    # often misused for path traversal
        "path.resolve",
        "process.env",                  # env var access (CWE-200 if leaked to client)
        "__proto__",                    # CWE-1321 prototype pollution
        "Object.assign",                # CWE-1321 if source is user input
        "RegExp(",                      # CWE-1333 ReDoS if user-controlled pattern
    ]
    njs_deps = [
        "express",                      # Express framework (overlaps with express-web)
        "fastify",
        "koa",
        "lodash",                       # CWE-1321 prototype pollution in old versions
        "jquery",                       # CWE-1321 $.extend
        "ejs",                          # CWE-1336 SSTI
        "pug",
        "nunjucks",
        "handlebars",
        "vm2",                          # deprecated, vulnerable sandbox
        "isolated-vm",                  # safer sandbox (positive signal)
    ]
    njs_infra = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "tsconfig.json",
    ]

    return (
        _has_ext(ctx.exts, njs_exts)
        or _has_import(ctx.imports, njs_imports)
        or _has_dependency(ctx.deps, njs_deps)
        or _has_infra_file(ctx.infra_files, njs_infra)
    )


def _check_express_web(*args) -> bool:
    """Activate for Express.js web applications."""
    ctx = _DomainContext.from_args(args)

    exp_imports = [
        "express",                      # the framework
        "app.use(",                     # Express middleware mounting
        "app.get(",
        "app.post(",
        "app.put(",
        "app.patch(",
        "app.delete(",
        "router.get(",
        "router.post(",
        "express.json",
        "express.urlencoded",
        "express.static",
        "res.render",                   # template rendering (SSTI risk)
        "res.cookie",                   # cookie setting (insecure flag risk)
        "req.body",                     # body access (validation risk)
    ]
    exp_deps = [
        "express",
        "body-parser",
        "cookie-parser",
        "express-session",
        "cookie-session",
        "csurf",                        # deprecated but still used
        "csrf-csrf",                    # modern replacement
        "helmet",                       # security headers (positive signal)
        "cors",                         # CORS config (misconfig risk)
        "ejs",                          # template engines
        "pug",
        "nunjucks",
        "handlebars",
        "multer",                       # file upload
    ]
    exp_infra = [
        "app.js",
        "server.js",
        "index.js",
        "src/app.js",
        "src/server.js",
    ]

    return (
        _has_import(ctx.imports, exp_imports)
        or _has_dependency(ctx.deps, exp_deps)
        or _has_infra_file(ctx.infra_files, exp_infra)
    )


def _check_nextjs_app(*args) -> bool:
    """Activate for Next.js applications (App Router or Pages Router)."""
    ctx = _DomainContext.from_args(args)

    nxt_imports = [
        "next/server",                  # Next.js server utilities
        "next/navigation",
        "next/headers",
        "next/image",                   # Image optimization (SSRF risk)
        "next/link",
        "next/router",
        "next/document",
        "next/script",
        "NextResponse",                 # Next.js response class
        "NextRequest",
        "getServerSideProps",           # Pages Router SSR (data leak risk)
        "getStaticProps",
        "getInitialProps",
        "use server",                   # Server Actions (Next.js 14+)
        "searchParams",                 # App Router searchParams
    ]
    nxt_deps = [
        "next",
        "next-auth",
        "@auth/core",
    ]
    nxt_infra = [
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "middleware.ts",
        "middleware.js",
        "src/middleware.ts",
        "src/middleware.js",
        "src/app/layout.tsx",
        "src/app/layout.js",
        "src/app/page.tsx",
        "src/app/page.js",
        "src/app/route.ts",
        "src/app/route.js",
        "pages/_app.js",
        "pages/_app.tsx",
        "pages/api/",
    ]

    return (
        _has_import(ctx.imports, nxt_imports)
        or _has_dependency(ctx.deps, nxt_deps)
        or _has_infra_file(ctx.infra_files, nxt_infra)
    )


def _check_python_runtime(*args) -> bool:
    """Activate for Python codebases using runtime-unsafe APIs."""
    ctx = _DomainContext.from_args(args)

    pyr_exts = [".py", ".pyw", ".pyi"]
    pyr_imports = [
        "import os",                    # os.system (CWE-78)
        "import subprocess",            # subprocess shell=True (CWE-78)
        "from subprocess",
        "import pickle",                # pickle.loads (CWE-502)
        "import cPickle",               # Python 2 pickle (CWE-502)
        "import yaml",                  # yaml.load (CWE-502)
        "import marshal",               # marshal.loads (CWE-502)
        "import shelve",                # shelve uses pickle (CWE-502)
        "import ctypes",                # ctypes abuse (CWE-78)
        "import requests",              # SSRF risk
        "import urllib",                # SSRF risk
        "from urllib",
        "import httpx",                 # SSRF risk
        "import aiohttp",               # SSRF risk
        "eval(",                        # CWE-95 code injection
        "exec(",                        # CWE-95
        "compile(",                     # CWE-95
        "import re",                    # ReDoS risk
        "tempfile.mktemp",              # CWE-377 race condition
    ]
    pyr_deps = [
        "requests",
        "urllib3",
        "httpx",
        "aiohttp",
        "pyyaml",                       # yaml.load risk
        "pickle",                       # stdlib but listed for clarity
        "google-re2",                   # positive signal (ReDoS mitigation)
    ]
    pyr_infra = [
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "requirements.txt",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "tox.ini",
    ]

    return (
        _has_ext(ctx.exts, pyr_exts)
        or _has_import(ctx.imports, pyr_imports)
        or _has_dependency(ctx.deps, pyr_deps)
        or _has_infra_file(ctx.infra_files, pyr_infra)
    )


def _check_django_hardening(*args) -> bool:
    """Activate for Django applications."""
    ctx = _DomainContext.from_args(args)

    djg_imports = [
        "django",                       # the framework
        "from django",
        "import django",
        "django.http",
        "django.conf",
        "django.shortcuts",
        "django.views",
        "django.middleware",
        "django.contrib",
        "django.db.models",
        "django.template",
        "django.urls",
        "Model.objects.raw",            # SQL injection risk
        "cursor.execute",
        "csrf_exempt",                  # CSRF bypass risk
        "autoescape off",               # XSS risk in templates
    ]
    djg_deps = [
        "django",
        "Django",
        "django-rest-framework",
        "djangorestframework",
        "django-cors-headers",
        "django-debug-toolbar",         # debug code risk
        "django-extensions",
        "celery",                       # often paired with Django
        "gunicorn",                     # Django app server
        "whitenoise",                   # Django static files
    ]
    djg_infra = [
        "manage.py",
        "wsgi.py",
        "asgi.py",
        "settings.py",
        "settings/__init__.py",
        "settings/base.py",
        "settings/production.py",
        "urls.py",
    ]

    return (
        _has_import(ctx.imports, djg_imports)
        or _has_dependency(ctx.deps, djg_deps)
        or _has_infra_file(ctx.infra_files, djg_infra)
    )


def _check_flask_hardening(*args) -> bool:
    """Activate for Flask applications."""
    ctx = _DomainContext.from_args(args)

    flk_imports = [
        "from flask",                   # the framework
        "import flask",
        "flask.Flask",
        "flask.request",
        "flask.session",
        "flask.render_template",
        "flask.render_template_string", # SSTI risk
        "flask.redirect",
        "flask.url_for",
        "flask.abort",
        "flask.send_file",              # path traversal risk
        "flask.send_from_directory",
        "app.run(",                     # debug mode risk
        "app.debug",
        "app.config[",                  # config access (SECRET_KEY risk)
        "cursor.execute",               # SQL injection risk (raw SQL)
        "db.session.execute",           # SQLAlchemy raw SQL
    ]
    flk_deps = [
        "flask",
        "Flask",
        "flask-wtf",                    # CSRF protection (positive signal)
        "flask-sqlalchemy",              # ORM
        "flask-login",                   # auth
        "flask-session",                 # server-side sessions
        "flask-jwt-extended",
        "flask-cors",
        "flask-limiter",
        "werkzeug",                     # Flask's WSGI lib (debugger RCE risk)
    ]
    flk_infra = [
        "app.py",
        "wsgi.py",
        "asgi.py",
        "flaskr/__init__.py",
        "requirements.txt",
    ]

    return (
        _has_import(ctx.imports, flk_imports)
        or _has_dependency(ctx.deps, flk_deps)
        or _has_infra_file(ctx.infra_files, flk_infra)
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# New domain checkers (2026-07-12)
# ---------------------------------------------------------------------------


def _check_cdn_cache_security(*args) -> bool:
    """Activate for projects using a CDN/edge cache layer."""
    ctx = _DomainContext.from_args(args)

    cdn_infra = ["cloudfront", "cloudflare", "fastly", "akamai", "cdn", "edge", "varnish", "cloudflare"]
    cdn_deps = ["cloudfront", "fastly", "cloudflare", "boto3"]
    cdn_imports = ["cloudfront", "fastly", "cloudflare", "cdn"]

    return (
        _has_infra_file(ctx.infra_files, cdn_infra)
        or _has_dependency(ctx.deps, cdn_deps)
        or _has_import(ctx.imports, cdn_imports)
    )


def _check_dns_security(*args) -> bool:
    """Activate for projects managing DNS zones."""
    ctx = _DomainContext.from_args(args)

    dns_infra = ["route53", "dns", "zone-file", "named.conf", "cloudflare"]
    dns_deps = ["dnspython", "dns", "ns1", "dyn", "route53", "boto3"]
    dns_imports = ["dns", "route53", "ns1", "dnspython"]

    return (
        _has_infra_file(ctx.infra_files, dns_infra)
        or _has_dependency(ctx.deps, dns_deps)
        or _has_import(ctx.imports, dns_imports)
    )


def _check_email_authentication(*args) -> bool:
    """Activate for projects that send email."""
    ctx = _DomainContext.from_args(args)

    email_deps = ["sendgrid", "mailgun", "ses", "sparkpost", "postmark", "mailchimp", "aiosmtplib", "django.core.mail"]
    email_imports = ["smtplib", "sendgrid", "ses", "mailgun", "email.mime", "aiosmtplib"]

    return (
        _has_dependency(ctx.deps, email_deps)
        or _has_import(ctx.imports, email_imports)
    )


def _check_push_notification_security(*args) -> bool:
    """Activate for projects using push notifications (FCM/APNs)."""
    ctx = _DomainContext.from_args(args)

    push_deps = ["firebase", "fcm", "apns", "pyfcm", "python-push-notify", "firebase-admin"]
    push_imports = ["firebase_admin", "apns", "fcm", "firebase"]

    return (
        _has_dependency(ctx.deps, push_deps)
        or _has_import(ctx.imports, push_imports)
    )


def _check_saml_sso_security(*args) -> bool:
    """Activate for projects using SAML SSO."""
    ctx = _DomainContext.from_args(args)

    saml_deps = ["pysaml2", "onelogin", "python3-saml", "spring-security-saml2", "saml2", "leptoplast"]
    saml_imports = ["saml", "SAML", "OneLogin", "saml2", "onelogin"]

    return (
        _has_dependency(ctx.deps, saml_deps)
        or _has_import(ctx.imports, saml_imports)
    )


def _check_secrets_runtime_management(*args) -> bool:
    """Activate for projects using runtime secrets backends."""
    ctx = _DomainContext.from_args(args)

    secrets_deps = ["hvac", "boto3", "google-cloud-secret-manager", "azure-keyvault", "vault", "aws-secretsmanager"]
    secrets_imports = ["vault", "secretsmanager", "keyvault", "hvac", "google.cloud.secretmanager"]

    return (
        _has_dependency(ctx.deps, secrets_deps)
        or _has_import(ctx.imports, secrets_imports)
    )


def _check_service_mesh_security(*args) -> bool:
    """Activate for projects deployed on a service mesh (Istio/Linkerd)."""
    ctx = _DomainContext.from_args(args)

    mesh_infra = ["istio", "linkerd", "virtualservice", "destinationrule", "peerauthoration", "authorizationpolicy"]
    mesh_deps = ["istio-client", "linkerd2"]
    mesh_imports = ["istio", "linkerd"]

    return (
        _has_infra_file(ctx.infra_files, mesh_infra)
        or _has_dependency(ctx.deps, mesh_deps)
        or _has_import(ctx.imports, mesh_imports)
    )


def _check_kubernetes_hardening(*args) -> bool:
    """Activate for projects deployed on Kubernetes."""
    ctx = _DomainContext.from_args(args)

    k8s_infra = ["deployment.yaml", "service.yaml", "statefulset.yaml", "daemonset.yaml",
                 "role.yaml", "clusterrole.yaml", "networkpolicy.yaml", "helmfile.yaml",
                 "chart.yaml", "values.yaml", "kustomization.yaml"]
    k8s_imports = ["kubernetes", "kubectl", "kube", "helm"]
    k8s_deps = ["kubernetes", "pykube", "lightkube", "helm"]

    has_k8s_yaml = any(
        "k8s" in f.lower() or "kubernetes" in f.lower() or "deploy" in f.lower()
        for f in ctx.infra_files
    )

    return (
        _has_infra_file(ctx.infra_files, k8s_infra)
        or has_k8s_yaml
        or _has_import(ctx.imports, k8s_imports)
        or _has_dependency(ctx.deps, k8s_deps)
    )


# ---------------------------------------------------------------------------
# Auto-generated checkers for 253 remaining domains (2026-08-06)
# ---------------------------------------------------------------------------
_GENERATED_CHECKERS: dict[str, _DomainCheckerFn] = {}
try:
    import patchi.core.brain._generated_checkers as _gen_mod
    for _name in dir(_gen_mod):
        if _name.startswith("_check_"):
            _fn = getattr(_gen_mod, _name)
            if callable(_fn):
                # Extract domain slug from function name: _check_foo_bar -> foo-bar
                _slug = _name[7:].replace("_", "-")
                _GENERATED_CHECKERS[_slug] = _fn
except ImportError:
    pass


# ---------------------------------------------------------------------------
# New domain checkers — 27 additional technology-stack domains (2026-07-12)
# ---------------------------------------------------------------------------


def _check_access_control_authz(*args) -> bool:
    """Activate for projects with role/permission checks, admin routes, or multi-tenant data."""
    ctx = _DomainContext.from_args(args)

    az_imports = [
        "authorize", "permission", "has_role", "has_permission", "is_admin",
        "check_access", "rbac", "acl", "can_access", "require_role",
        "login_required", "permission_required", "@requires_permissions",
        "CurrentPrincipal", "SecurityContext", "AuthorizationService",
        "policy.enforce", "guard.can", "authz",
    ]
    az_deps = [
        "casbin", "pycasbin", "rbac", "accesscontrol", "casbin-rs",
        "spring-security", "django-guardian", "django-rules", "pundit",
        "cancancan", "policy_machine",
    ]

    return (
        _has_import(ctx.imports, az_imports)
        or _has_dependency(ctx.deps, az_deps)
        or _has_config_key(ctx.config_keys, ["rbac", "permissions", "roles", "authorization"])
    )


def _check_agent_orchestration(*args) -> bool:
    """Activate for multi-agent / agentic-loop frameworks (LangGraph, CrewAI, AutoGen)."""
    ctx = _DomainContext.from_args(args)

    agt_deps = [
        "langgraph", "crewai", "autogen", "openai-agents", "swarm",
        "semantic-kernel", "langchain", "llamaindex",
    ]
    agt_imports = [
        "langgraph", "crewai", "autogen", "AgentExecutor", "ToolNode",
        "create_react_agent", "StateGraph", "AgentGroupChat",
        "openai.agents", "Swarm",
    ]

    return (
        _has_import(ctx.imports, agt_imports)
        or _has_dependency(ctx.deps, agt_deps)
    )


def _check_auth_session(*args) -> bool:
    """Activate for projects with session management, login, password handling, or JWT."""
    ctx = _DomainContext.from_args(args)

    as_deps = [
        "express-session", "cookie-session", "passport", "next-auth",
        "flask-login", "flask-session", "django.contrib.sessions",
        "devise", "warden", "spring-security", "jsonwebtoken", "pyjwt",
        "jose", "ruby-jwt", "jjwt", "bcrypt", "argon2-cffi", "passlib",
    ]
    as_imports = [
        "login", "signin", "session.create", "session.destroy",
        "bcrypt", "argon2", "password_hash", "check_password",
        "jwt.verify", "jwt.decode", "jwt.sign",
        "passport.authenticate", "sessions.create",
        "LoginView", "LoginController", "authenticat",
    ]

    return (
        _has_import(ctx.imports, as_imports)
        or _has_dependency(ctx.deps, as_deps)
    )


def _check_cicd_pipeline(*args) -> bool:
    """Activate for repos with CI/CD configuration files."""
    ctx = _DomainContext.from_args(args)

    ci_infra = [
        ".github/workflows", ".gitlab-ci.yml", "jenkinsfile",
        ".circleci/config.yml", "azure-pipelines.yml",
        "bitbucket-pipelines.yml", ".travis.yml", "buildkite.yml",
        "cloudbuild.yaml", ".drone.yml", "taskcluster.yml",
    ]

    return _has_infra_file(ctx.infra_files, ci_infra)


def _check_configuration_hardening(*args) -> bool:
    """Activate for projects with deployable server config or secrets usage."""
    ctx = _DomainContext.from_args(args)

    ch_infra = [
        "nginx.conf", "apache2.conf", "httpd.conf", ".env",
        ".env.production", ".env.local", "config.yaml", "config.yml",
        "application.yml", "application.properties",
    ]
    ch_imports = [
        "os.environ", "process.env", "dotenv", "load_dotenv",
        "config.get", "configparser", "yaml.safe_load",
        "getenv", "environ",
    ]

    return (
        _has_infra_file(ctx.infra_files, ch_infra)
        or _has_import(ctx.imports, ch_imports)
        or _has_config_key(ctx.config_keys, ["secret", "password", "api_key", "token", "credentials"])
    )


def _check_container_infra(*args) -> bool:
    """Activate for projects with Dockerfiles, docker-compose, or K8s manifests."""
    ctx = _DomainContext.from_args(args)

    ci_infra = [
        "dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "compose.yaml", "compose.yml", ".dockerignore",
        "deployment.yaml", "service.yaml", "statefulset.yaml",
        "daemonset.yaml", "chart.yaml", "values.yaml", "kustomization.yaml",
        "helmfile.yaml",
    ]

    return (
        _has_infra_file(ctx.infra_files, ci_infra)
        or _has_import(ctx.imports, ["docker", "kubernetes", "kubectl", "helm"])
    )


def _check_data_layer(*args) -> bool:
    """Activate for projects using databases (drivers, ORMs, migrations)."""
    ctx = _DomainContext.from_args(args)

    dl_deps = [
        "sqlalchemy", "psycopg2", "asyncpg", "mysqlclient", "pymysql",
        "pymongo", "motor", "django", "prisma", "typeorm", "sequelize",
        "knex", "sequelize", "pg", "mysql2", "better-sqlite3",
        "sqlite3", "alembic", "django.db", "drizzle-orm",
    ]
    dl_imports = [
        "sqlalchemy", "psycopg2", "asyncpg", "pymysql", "pymongo",
        "mongoose", "prisma", "typeorm", "sequelize", "knex",
        "cursor.execute", "db.session", "connection.execute",
        "create_engine", "sessionmaker", "Base.metadata",
        "migration", "alembic", "db:migrate",
    ]

    return (
        _has_import(ctx.imports, dl_imports)
        or _has_dependency(ctx.deps, dl_deps)
    )


def _check_data_protection_privacy(*args) -> bool:
    """Activate for projects handling PII, client-side storage, or caching layers."""
    ctx = _DomainContext.from_args(args)

    dp_deps = [
        "cookie", "redis", "memcached", "localforage",
        "client-session", "express-session",
    ]
    dp_imports = [
        "localStorage", "sessionStorage", "indexedDB",
        "cookies.set", "cookies.get", "setCookie",
        "cache", "Cache-Control", "Vary",
        "pii", "personal_data", "gdpr", "ccpa",
    ]

    return (
        _has_import(ctx.imports, dp_imports)
        or _has_dependency(ctx.deps, dp_deps)
        or _has_config_key(ctx.config_keys, ["privacy", "pii", "gdpr", "ccpa", "data_protection"])
    )


def _check_desktop_app(*args) -> bool:
    """Activate for Electron desktop applications."""
    ctx = _DomainContext.from_args(args)

    da_deps = ["electron", "electron-builder", "electron-forge", "electron-packager"]
    da_imports = [
        "BrowserWindow", "electron", "ipcMain", "ipcRenderer",
        "contextBridge", "webContents", "app.getPath", "shell.openExternal",
    ]
    da_infra = ["electron-builder.yml", "electron-builder.yaml", "forge.config.js"]

    return (
        _has_import(ctx.imports, da_imports)
        or _has_dependency(ctx.deps, da_deps)
        or _has_infra_file(ctx.infra_files, da_infra)
    )


def _check_file_handling(*args) -> bool:
    """Activate for projects with file upload/download or archive extraction."""
    ctx = _DomainContext.from_args(args)

    fh_imports = [
        "multer", "busboy", "formidable", "multipart",
        "zip", "tar", "gunzip", "zlib", "adm-zip", "unzipper",
        "send_file", "sendFile", "Content-Disposition",
        "open(", "write(", "os.path.join", "path.join",
    ]
    fh_deps = [
        "multer", "busboy", "formidable", "archiver", "adm-zip",
        "node-tar", "unzipper", "yauzl", "yazl",
    ]

    return (
        _has_import(ctx.imports, fh_imports)
        or _has_dependency(ctx.deps, fh_deps)
    )


def _check_general_cryptography(*args) -> bool:
    """Activate for projects using crypto libraries or encryption."""
    ctx = _DomainContext.from_args(args)

    gc_imports = [
        "crypto", "hashlib", "hmac", "cryptography", "openssl",
        "libsodium", "bcrypt", "argon2", "scrypt", "pbkdf2",
        "AES", "RSA", "ECDSA", "HMAC",
        "from cryptography", "import hashlib",
        "subtle.encrypt", "subtle.decrypt", "subtle.sign",
    ]
    gc_deps = [
        "cryptography", "pycryptodome", "libsodium", "bcrypt",
        "argon2-cffi", "node-forge", "sjcl", "noble", "@noble/hashes",
    ]

    return (
        _has_import(ctx.imports, gc_imports)
        or _has_dependency(ctx.deps, gc_deps)
    )


def _check_github_app_bot(*args) -> bool:
    """Activate for repos operating GitHub Apps or bots with automated PR/issue actions."""
    ctx = _DomainContext.from_args(args)

    gh_deps = [
        "@octokit/auth-app", "@octokit/rest", "pygithub",
        "probot", "github-app",
    ]
    gh_imports = [
        "octokit", "App", "createAppAuth", "getInstallationAccessToken",
        "pull_request_target", "workflow_run",
    ]
    gh_infra = [".github/workflows"]

    return (
        _has_import(ctx.imports, gh_imports)
        or _has_dependency(ctx.deps, gh_deps)
        or _has_infra_file(ctx.infra_files, gh_infra)
    )


def _check_graphql_api_security(*args) -> bool:
    """Activate for projects exposing GraphQL endpoints."""
    ctx = _DomainContext.from_args(args)

    gql_deps = [
        "graphql", "apollo-server", "@apollo/server", "graphene",
        "strawberry-graphql", "ariadne", "hasura", "type-graphql",
    ]
    gql_imports = [
        "GraphQLSchema", "graphql", "apollo-server", "gql",
        "strawberry", "ariadne", "buildSchema", "makeExecutableSchema",
    ]
    gql_infra = [".graphql", ".gql", "schema.graphql", "schema.gql"]

    return (
        _has_import(ctx.imports, gql_imports)
        or _has_dependency(ctx.deps, gql_deps)
        or _has_infra_file(ctx.infra_files, gql_infra)
    )


def _check_input_validation_business_logic(*args) -> bool:
    """Activate for projects with multi-step business flows or validation logic."""
    ctx = _DomainContext.from_args(args)

    iv_deps = [
        "joi", "yup", "zod", "ajv", "class-validator", "marshmallow",
        "pydantic", "cerberus", "jsonschema", "express-validator",
        "drf-validation", "django.forms",
    ]
    iv_imports = [
        "validate", "sanitize", "whitelist", "blacklist",
        "InputValidator", "RequestValidator", "Schema.validate",
        "checkConstraint", "assertValid",
    ]

    return (
        _has_import(ctx.imports, iv_imports)
        or _has_dependency(ctx.deps, iv_deps)
    )


def _check_llm_integration(*args) -> bool:
    """Activate for projects using LLM SDKs, vector DBs, or prompt templates."""
    ctx = _DomainContext.from_args(args)

    llm_deps = [
        "openai", "anthropic", "@anthropic-ai/sdk", "langchain",
        "llamaindex", "google-generativeai", "cohere-ai", "transformers",
        "pinecone-client", "chromadb", "weaviate-client", "qdrant-client",
        "pgvector", "faiss",
    ]
    llm_imports = [
        "openai", "anthropic", "ChatOpenAI", "OpenAIEmbeddings",
        "PineconeVectorStore", "Chroma", "FAISS",
        "generateText", "generateContent", "messages.create",
    ]

    return (
        _has_import(ctx.imports, llm_imports)
        or _has_dependency(ctx.deps, llm_deps)
    )


def _check_logging_error_handling(*args) -> bool:
    """Activate for projects with logging libraries and error handling middleware."""
    ctx = _DomainContext.from_args(args)

    le_deps = [
        "winston", "pino", "bunyan", "log4j", "logback",
        "slog", "zap", "logrus", "structlog", "loguru",
    ]
    le_imports = [
        "logging", "logger", "log.error", "log.warn", "log.info",
        "winston.createLogger", "pino", "console.error",
        "errorHandler", "ErrorMiddleware", "onerror",
        "try:", "catch", "except", "rescue",
    ]

    return (
        _has_import(ctx.imports, le_imports)
        or _has_dependency(ctx.deps, le_deps)
    )


def _check_mcp_tool_surface(*args) -> bool:
    """Activate for projects implementing an MCP server (Model Context Protocol)."""
    ctx = _DomainContext.from_args(args)

    mcp_deps = ["mcp", "@modelcontextprotocol/sdk"]
    mcp_imports = [
        "mcp.server", "MCPServer", "tools/list", "tools/call",
        "resources/list", "resources/read", "prompts/list",
        "ListToolsRequest", "CallToolRequest", "ServerSession",
    ]

    return (
        _has_import(ctx.imports, mcp_imports)
        or _has_dependency(ctx.deps, mcp_deps)
    )


def _check_message_queue_event_driven(*args) -> bool:
    """Activate for projects using message brokers (Kafka, RabbitMQ, SQS, Pub/Sub)."""
    ctx = _DomainContext.from_args(args)

    mq_deps = [
        "kafkajs", "kafka-node", "kafka-python", "confluent-kafka",
        "amqplib", "pika", "rabbitmq", "celery",
        "boto3", "aws-sdk", "sqs", "sns",
        "google-cloud-pubsub", "nats", "bull", "bullmq", "redis",
    ]
    mq_imports = [
        "kafka", "KafkaJS", "Consumer", "Producer", "Broker",
        "pika", "amqplib", "celery",
        "SQS", "sqs", "SNS", "sns",
        "PubSub", "pubsub", "Subscriber",
        "nats.connect", "Bull",
    ]

    return (
        _has_import(ctx.imports, mq_imports)
        or _has_dependency(ctx.deps, mq_deps)
    )


def _check_mobile(*args) -> bool:
    """Activate for Android/iOS or cross-platform mobile (React Native/Flutter/Xamarin)."""
    ctx = _DomainContext.from_args(args)

    mob_deps = [
        "react-native", "flutter", "xamarin", "ionic", "capacitor",
        "cordova", "expo", "@ionic/core",
    ]
    mob_imports = [
        "ReactNative", "react-native", "flutter", "dart:ui",
        "Xamarin.Forms", "Capacitor", "Ionic",
    ]
    mob_infra = [
        "androidmanifest.xml", "info.plist", "pubspec.yaml",
        "config.xml", "build.gradle", "app.json",
        "android/app", "ios/app",
    ]

    return (
        _has_import(ctx.imports, mob_imports)
        or _has_dependency(ctx.deps, mob_deps)
        or _has_infra_file(ctx.infra_files, mob_infra)
        or ctx.has_mobile
    )


def _check_oauth_oidc(*args) -> bool:
    """Activate for projects using OAuth 2.0 or OpenID Connect."""
    ctx = _DomainContext.from_args(args)

    oa_deps = [
        "passport", "passport-oauth2", "next-auth", "authlib",
        "django-allauth", "social-auth-app", "omniauth",
        "spring-security-oauth2", "oidc-client", "oidc",
    ]
    oa_imports = [
        "oauth", "OAuth", "OIDC", "openid", "OpenID",
        "passport.authenticate", "token.exchange",
        "authorization_code", "client_credentials",
        "refresh_token", "access_token",
        "googleapis/auth", "auth0",
    ]

    return (
        _has_import(ctx.imports, oa_imports)
        or _has_dependency(ctx.deps, oa_deps)
    )


def _check_secure_coding_architecture(*args) -> bool:
    """Activate for projects with multi-threaded/async code and third-party deps."""
    ctx = _DomainContext.from_args(args)

    sc_imports = [
        "threading", "multiprocessing", "concurrent.futures",
        "asyncio", "ThreadPoolExecutor", "ProcessPoolExecutor",
        "WorkerPool", "TaskGroup", "spawn",
    ]
    sc_deps = [
        "celery", "rq", "huey", "dramatiq",
        "gunicorn", "uvicorn", "hypercorn",
    ]

    return (
        _has_import(ctx.imports, sc_imports)
        or _has_dependency(ctx.deps, sc_deps)
        or len(list(ctx.deps)) > 5
    )


def _check_secure_communication_tls(*args) -> bool:
    """Activate for projects with HTTPS endpoints, mTLS, or TLS client connections."""
    ctx = _DomainContext.from_args(args)

    tls_imports = [
        "ssl", "tls", "https", "mTLS", "certificate",
        "SSLContext", "create_default_context", "CERT_REQUIRED",
        "verify=True", "verify_ssl",
    ]
    tls_deps = [
        "pyopenssl", "trustme", "certifi", "ssl",
    ]
    tls_config = ["ssl", "tls", "https", "certificate", "cert"]

    return (
        _has_import(ctx.imports, tls_imports)
        or _has_dependency(ctx.deps, tls_deps)
        or _has_config_key(ctx.config_keys, tls_config)
    )


def _check_self_contained_tokens(*args) -> bool:
    """Activate for projects issuing or validating JWT/SAML tokens."""
    ctx = _DomainContext.from_args(args)

    sct_deps = [
        "jsonwebtoken", "jose", "pyjwt", "ruby-jwt", "jjwt",
        "pysaml2", "python3-saml", "onelogin",
    ]
    sct_imports = [
        "jwt.sign", "jwt.verify", "jwt.decode",
        "JWS", "JWE", "JWK", "JWA",
        "saml2", "SAMLResponse", "Assertion",
        "RS256", "ES256", "HS256",
    ]

    return (
        _has_import(ctx.imports, sct_imports)
        or _has_dependency(ctx.deps, sct_deps)
    )


def _check_supply_chain_local_tool(*args) -> bool:
    """Activate for CLI tools with release pipelines or install scripts."""
    ctx = _DomainContext.from_args(args)

    sc_infra = [
        "goreleaser.yml", ".goreleaser.yml", "release.yml",
        "install.sh", "install.ps1",
    ]
    has_bin = any(
        "bin" in str(f).lower() for f in ctx.infra_files
    )

    return (
        _has_infra_file(ctx.infra_files, sc_infra)
        or has_bin
        or ctx.has_cli
    )


def _check_web_frontend(*args) -> bool:
    """Activate for browser-based frontends (React, Vue, Angular, Svelte)."""
    ctx = _DomainContext.from_args(args)

    wf_deps = [
        "react", "react-dom", "vue", "@vue/cli", "@angular/core",
        "svelte", "solid-js", "preact", "lit", "ember-cli",
    ]
    wf_imports = [
        "ReactDOM", "createRoot", "Vue.createApp",
        "angular.module", "Component", "OnInit",
        "svelte.mount", "render",
    ]
    wf_infra = [
        "webpack.config", "vite.config", "rollup.config",
        "next.config", "nuxt.config", "angular.json",
        "tsconfig.json", "index.html",
    ]

    return (
        _has_import(ctx.imports, wf_imports)
        or _has_dependency(ctx.deps, wf_deps)
        or _has_infra_file(ctx.infra_files, wf_infra)
    )


def _check_webrtc_communication(*args) -> bool:
    """Activate for projects running TURN servers or WebRTC media/signaling."""
    ctx = _DomainContext.from_args(args)

    wrtc_deps = [
        "simple-peer", "peerjs", "werift", "pion/webrtc",
        "mediasoup", "janus", "kurento", "coturn",
    ]
    wrtc_imports = [
        "RTCPeerConnection", "RTCSessionDescription",
        "webrtc", "PeerConnection", "MediaStream",
        "createOffer", "createAnswer", "addIceCandidate",
    ]

    return (
        _has_import(ctx.imports, wrtc_imports)
        or _has_dependency(ctx.deps, wrtc_deps)
    )


def _check_security_scanner_tool(*args) -> bool:
    """Activate for security scanner/analysis tools (SAST, DAST, SCA, agents)."""
    ctx = _DomainContext.from_args(args)

    scanner_imports = [
        "scan", "detect", "finding", "vulnerability", "cve",
        "semgrep", "bandit", "safety", "trivy", "grype",
        "BaseAgent", "AgentInput", "AgentResult",
        "coordinator", "governor", "dispatcher",
        "domain_activator", "domain_loader",
        "security_probe", "security_config",
    ]
    scanner_deps = [
        "semgrep", "bandit", "safety", "trivy", "grype",
        "syft", "cosign", "checkov", "tfsec", "kics",
    ]
    scanner_infra = [
        "domains/", "playbooks/", "fix-playbooks/",
        "sigma_rules/", "agents/", "security/",
    ]

    has_scanner_code = (
        _has_import(ctx.imports, scanner_imports)
        or _has_dependency(ctx.deps, scanner_deps)
    )
    has_scanner_structure = any(
        any(seg in f.lower() for seg in ["scan", "detect", "finding", "agent", "security"])
        for f in ctx.infra_files
    )

    return has_scanner_code or has_scanner_structure


def _check_websocket_security(*args) -> bool:
    """Activate for projects using WebSocket server or client libraries."""
    ctx = _DomainContext.from_args(args)

    ws_deps = [
        "ws", "socket.io", "sockjs", "websocket",
        "channels", "django-channels", "signalr",
    ]
    ws_imports = [
        "WebSocket", "Socket.IO", "socket.io", "ws.Server",
        "socketio", "SignalR", "channels",
        "on('connection')", "wss://",
    ]

    return (
        _has_import(ctx.imports, ws_imports)
        or _has_dependency(ctx.deps, ws_deps)
    )


# ---------------------------------------------------------------------------

# Type alias for clarity
_DomainCheckerFn = Callable[..., bool]

_DOMAIN_CHECKERS: dict[str, _DomainCheckerFn] = {
    # Original 13 technology-stack domains
    "native-code-safety": _check_native_code_safety,
    "go-concurrency": _check_go_concurrency,
    "jvm-hardening": _check_jvm_hardening,
    "mobile-native": _check_mobile_native,
    "ruby-rails": _check_ruby_rails,
    "svelte-ssr": _check_svelte_ssr,
    "cargo-supply-chain": _check_cargo_supply_chain,
    "nodejs-runtime": _check_nodejs_runtime,
    "express-web": _check_express_web,
    "nextjs-app": _check_nextjs_app,
    "python-runtime": _check_python_runtime,
    "django-hardening": _check_django_hardening,
    "flask-hardening": _check_flask_hardening,
    # 8 security-domain agents (added 2026-07-12)
    "cdn-cache-security": _check_cdn_cache_security,
    "dns-security": _check_dns_security,
    "email-authentication": _check_email_authentication,
    "push-notification-security": _check_push_notification_security,
    "saml-sso-security": _check_saml_sso_security,
    "secrets-runtime-management": _check_secrets_runtime_management,
    "service-mesh-security": _check_service_mesh_security,
    "kubernetes-hardening": _check_kubernetes_hardening,
    # 27 additional technology-stack domains (added 2026-07-12)
    "access-control-authz": _check_access_control_authz,
    "agent-orchestration": _check_agent_orchestration,
    "auth-session": _check_auth_session,
    "cicd-pipeline": _check_cicd_pipeline,
    "configuration-hardening": _check_configuration_hardening,
    "container-infra": _check_container_infra,
    "data-layer": _check_data_layer,
    "data-protection-privacy": _check_data_protection_privacy,
    "desktop-app": _check_desktop_app,
    "file-handling": _check_file_handling,
    "general-cryptography": _check_general_cryptography,
    "github-app-bot": _check_github_app_bot,
    "graphql-api-security": _check_graphql_api_security,
    "input-validation-business-logic": _check_input_validation_business_logic,
    "llm-integration": _check_llm_integration,
    "logging-error-handling": _check_logging_error_handling,
    "mcp-tool-surface": _check_mcp_tool_surface,
    "message-queue-event-driven": _check_message_queue_event_driven,
    "mobile": _check_mobile,
    "oauth-oidc": _check_oauth_oidc,
    "secure-coding-architecture": _check_secure_coding_architecture,
    "secure-communication-tls": _check_secure_communication_tls,
    "self-contained-tokens": _check_self_contained_tokens,
    "supply-chain-local-tool": _check_supply_chain_local_tool,
    "web-frontend": _check_web_frontend,
    "webrtc-communication": _check_webrtc_communication,
    "websocket-security": _check_websocket_security,
    "security-scanner-tool": _check_security_scanner_tool,
}

# Merge auto-generated checkers (253 domains) — existing entries take precedence
_DOMAIN_CHECKERS.update(
    {k: v for k, v in _GENERATED_CHECKERS.items() if k not in _DOMAIN_CHECKERS}
)


def activate_domains(
    args: Sequence,
    only: Iterable[str] | None = None,
) -> list[str]:
    """Return the sorted list of domain IDs that should activate for ``args``.

    Parameters
    ----------
    args:
        The 11-element tuple as described in :class:`_DomainContext`.
    only:
        Optional iterable of domain IDs to restrict the check to. ``None``
        means check all registered domains.
    """
    candidate_ids = list(only) if only is not None else list(_DOMAIN_CHECKERS)
    activated: list[str] = []
    for domain_id in candidate_ids:
        checker = _DOMAIN_CHECKERS.get(domain_id)
        if checker is None:
            continue
        try:
            if checker(*args):
                activated.append(domain_id)
        except Exception as e:
            # A single checker failure must not block other domains.
            # Log to the patchi worklog in a production deployment.
            _log.warning("activate_domains failed: %s", e)
            continue
    return sorted(activated)


# ---------------------------------------------------------------------------
# Legacy compatibility layer
# ---------------------------------------------------------------------------

_LANG_EXT_MAP: dict[str, str] = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".go": "golang",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".rb": "ruby",
    ".swift": "swift",
    ".svelte": "svelte",
    ".vue": "vue",
    ".dart": "dart",
}


def _infer_primary_language(exts: Iterable[str]) -> str:
    """Guess the primary language from observed file extensions."""
    counts: dict[str, int] = {}
    for ext in exts:
        lang = _LANG_EXT_MAP.get(ext.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return ""
    return max(counts, key=counts.get)


def _infer_app_type(
    active_domains: list[str],
    has_web: bool,
    has_cli: bool,
    has_mobile: bool,
) -> str:
    """Infer the project's application type from activated domains."""
    if has_mobile or "mobile" in active_domains or "mobile-native" in active_domains:
        return "mobile-app"
    if has_web:
        return "web-app"
    if has_cli:
        return "cli-tool"
    return "library"


def _infer_deployment(active_domains: list[str], infra_files: list[str]) -> str:
    """Infer deployment model from activated domains and infra files."""
    if "container-infra" in active_domains:
        return "containerized"
    if "cicd-pipeline" in active_domains:
        return "pipeline"
    has_kubernetes = any("k8s" in f.lower() or "kubernetes" in f.lower()
                          for f in infra_files)
    if has_kubernetes:
        return "kubernetes"
    has_docker = any("docker" in f.lower() for f in infra_files)
    if has_docker:
        return "docker"
    return "local"


def build_project_context(
    file_infos: Any = None,
    detected_imports: set[str] | None = None,
    dependency_names: set[str] | None = None,
    route_paths: list[str] | None = None,
    config_keys: set[str] | None = None,
    infrastructure_files: list[str] | None = None,
    has_web_framework: bool = False,
    has_cli_framework: bool = False,
    has_mobile_code: bool = False,
    file_extensions: set[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build a rich project context dict with discovered info and active domains.

    Legacy compatibility wrapper around :func:`activate_domains`.
    Accepts the same keyword parameters as the original
    ``patchi.core.brain.domain_activator.build_project_context``.
    """
    exts = sorted(file_extensions or [])
    args = [
        _infer_primary_language(exts),        # language
        "",                                     # framework (inferred elsewhere)
        list(detected_imports or []),           # imports
        list(dependency_names or []),           # deps
        list(route_paths or []),                # routes
        list(config_keys or []),                # config_keys
        list(infrastructure_files or []),       # infra_files
        bool(has_web_framework),                # has_web
        bool(has_cli_framework),                # has_cli
        bool(has_mobile_code),                  # has_mobile
        exts,                                   # exts
    ]
    active = activate_domains(args)

    context: dict[str, Any] = {
        "relevant_domains": active,
        "app_type": _infer_app_type(active, has_web_framework, has_cli_framework, has_mobile_code),
        "deployment_model": _infer_deployment(active, infrastructure_files or []),
        "has_user_auth": "auth-session" in active or "oauth-oidc" in active,
        "active_domain_count": len(active),
    }
    return context


__all__ = [
    "_DomainContext",
    "_DOMAIN_CHECKERS",
    "_has_import",
    "_has_dependency",
    "_has_ext",
    "_has_infra_file",
    "_has_config_key",
    "activate_domains",
    # Original 13
    "_check_native_code_safety",
    "_check_go_concurrency",
    "_check_jvm_hardening",
    "_check_mobile_native",
    "_check_ruby_rails",
    "_check_svelte_ssr",
    "_check_cargo_supply_chain",
    "_check_nodejs_runtime",
    "_check_express_web",
    "_check_nextjs_app",
    "_check_python_runtime",
    "_check_django_hardening",
    "_check_flask_hardening",
    # 8 security-domain agents
    "_check_cdn_cache_security",
    "_check_dns_security",
    "_check_email_authentication",
    "_check_push_notification_security",
    "_check_saml_sso_security",
    "_check_secrets_runtime_management",
    "_check_service_mesh_security",
    "_check_kubernetes_hardening",
    # 27 additional technology-stack domains
    "_check_access_control_authz",
    "_check_agent_orchestration",
    "_check_auth_session",
    "_check_cicd_pipeline",
    "_check_configuration_hardening",
    "_check_container_infra",
    "_check_data_layer",
    "_check_data_protection_privacy",
    "_check_desktop_app",
    "_check_file_handling",
    "_check_general_cryptography",
    "_check_github_app_bot",
    "_check_graphql_api_security",
    "_check_input_validation_business_logic",
    "_check_llm_integration",
    "_check_logging_error_handling",
    "_check_mcp_tool_surface",
    "_check_message_queue_event_driven",
    "_check_mobile",
    "_check_oauth_oidc",
    "_check_secure_coding_architecture",
    "_check_secure_communication_tls",
    "_check_self_contained_tokens",
    "_check_supply_chain_local_tool",
    "_check_web_frontend",
    "_check_webrtc_communication",
    "_check_websocket_security",
]
