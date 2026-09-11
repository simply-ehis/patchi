"""
AppDiscoveryAgent — Universal project detection and launch for testing.

Detects what type of project it is (web, desktop, CLI, mobile, etc.),
starts it up with the appropriate command, and exposes a target that
visual/browser testing agents can use.

Returns a Target object with:
- type: "http" | "desktop" | "cli"
- url: HTTP URL for web apps (None for desktop/CLI)
- pid: Process ID for desktop/CLI apps (None for web)
- screenshot_mode: "playwright" | "os" | "none"
- health_check: function to verify the app is running
"""

from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    register,
)
from ..brain.trace_log import trace_agent

_log = logging.getLogger("patchi.testing.app_discovery")


@dataclass
class AppTarget:
    """A launchable app target for testing."""

    type: str  # "http" | "desktop" | "cli"
    url: str | None = None  # For HTTP apps
    pid: int | None = None  # For desktop/CLI apps
    screenshot_mode: str = "playwright"  # "playwright" | "os" | "none"
    health_check: Callable[[], bool] = lambda: True
    process: subprocess.Popen | None = None
    port: int | None = None
    metadata: dict = field(default_factory=dict)

    def is_running(self) -> bool:
        if self.type == "http":
            return self._check_http()
        elif self.type == "desktop":
            return self._check_process()
        elif self.type == "cli":
            return self._check_process()
        return False

    def _check_http(self) -> bool:
        if not self.url:
            return False
        try:
            import urllib.request
            req = urllib.request.Request(self.url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status < 500
        except Exception:
            return False

    def _check_process(self) -> bool:
        if not self.pid:
            return False
        try:
            os.kill(self.pid, 0)
            return True
        except OSError:
            return False

    def cleanup(self) -> None:
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception:
                pass


@dataclass
class DetectedProject:
    """What we discovered about the project."""

    project_type: str  # "web", "desktop", "cli", "mobile", "library"
    framework: str | None = None
    start_command: str | None = None
    health_method: str = "http"  # "http" | "tcp" | "process" | "stdout"
    port: int | None = None
    working_dir: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    screenshot_capable: bool = False
    metadata: dict = field(default_factory=dict)


class FrameworkDetector:
    """Enhanced framework detection for all project types."""

    @staticmethod
    def detect(root: Path) -> DetectedProject:
        project = DetectedProject(working_dir=root)

        # Web: Node.js frameworks
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                import json
                pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                scripts = pkg.get("scripts", {})

                # Check for various frameworks
                if "next" in deps:
                    project.framework = "nextjs"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or "npm run dev"
                    project.health_method = "http"
                    project.port = FrameworkDetector._extract_port(scripts.get("dev", "")) or 3000
                elif "vite" in deps:
                    project.framework = "vite"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or "npm run dev"
                    project.health_method = "http"
                    project.port = 5173
                elif "react-scripts" in deps:
                    project.framework = "cra"
                    project.project_type = "web"
                    project.start_command = scripts.get("start") or "npm start"
                    project.health_method = "http"
                    project.port = 3000
                elif "nuxt" in deps:
                    project.framework = "nuxt"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or "npm run dev"
                    project.health_method = "http"
                    project.port = 3000
                elif "sveltekit" in deps:
                    project.framework = "sveltekit"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or "npm run dev"
                    project.health_method = "http"
                    project.port = 5173
                elif "astro" in deps:
                    project.framework = "astro"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or "npm run dev"
                    project.health_method = "http"
                    project.port = 4321
                elif "electron" in deps:
                    project.framework = "electron"
                    project.project_type = "desktop"
                    project.start_command = "electron ."
                    project.health_method = "process"
                    project.screenshot_capable = True
                elif "tauri" in deps or (root / "src-tauri").exists():
                    project.framework = "tauri"
                    project.project_type = "desktop"
                    project.start_command = "cargo tauri dev"
                    project.health_method = "process"
                    project.screenshot_capable = True
                elif "expo" in deps:
                    project.framework = "expo"
                    project.project_type = "mobile"
                    project.start_command = "expo start --web"
                    project.health_method = "http"
                    project.port = 19006
                elif "ionic" in deps:
                    project.framework = "ionic"
                    project.project_type = "mobile"
                    project.start_command = "ionic serve"
                    project.health_method = "http"
                    project.port = 8100
                elif "flutter" in deps:
                    project.framework = "flutter"
                    project.project_type = "mobile"
                    project.start_command = "flutter run -d web-server"
                    project.health_method = "http"
                    project.port = 8080
                elif "express" in deps or "fastify" in deps or "koa" in deps or "hono" in deps:
                    project.framework = "node"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or scripts.get("start") or "npm start"
                    project.health_method = "http"
                    project.port = FrameworkDetector._extract_port(scripts.get("dev", "") or scripts.get("start", "")) or 3000
                else:
                    project.framework = "node"
                    project.project_type = "web"
                    project.start_command = scripts.get("dev") or scripts.get("start") or "npm start"
                    project.health_method = "http"
                    project.port = 3000
            except Exception:
                pass

        # Web: Python frameworks
        if not project.framework:
            if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
                try:
                    content = ""
                    for f in ["pyproject.toml", "requirements.txt", "setup.py"]:
                        if (root / f).exists():
                            content += (root / f).read_text(encoding="utf-8", errors="ignore")

                    if "fastapi" in content:
                        project.framework = "fastapi"
                        project.project_type = "web"
                        project.start_command = "uvicorn app.main:app --host 127.0.0.1 --port {port}"
                        project.health_method = "http"
                        project.port = 8000
                    elif "flask" in content:
                        project.framework = "flask"
                        project.project_type = "web"
                        project.start_command = "flask run --host=127.0.0.1 --port={port}"
                        project.health_method = "http"
                        project.port = 5000
                    elif "django" in content and (root / "manage.py").exists():
                        project.framework = "django"
                        project.project_type = "web"
                        project.start_command = "python manage.py runserver 127.0.0.1:{port}"
                        project.health_method = "http"
                        project.port = 8000
                    elif "streamlit" in content:
                        project.framework = "streamlit"
                        project.project_type = "web"
                        project.start_command = "streamlit run app.py --server.port {port}"
                        project.health_method = "http"
                        project.port = 8501
                    elif "gradio" in content:
                        project.framework = "gradio"
                        project.project_type = "web"
                        project.start_command = "python app.py"
                        project.health_method = "http"
                        project.port = 7860
                    elif "nicegui" in content:
                        project.framework = "nicegui"
                        project.project_type = "web"
                        project.start_command = "python app.py"
                        project.health_method = "http"
                        project.port = 8080
                    elif "toga" in content:
                        project.framework = "toga"
                        project.project_type = "desktop"
                        project.start_command = "python -m toga"
                        project.health_method = "process"
                        project.screenshot_capable = True
                    elif "kivy" in content:
                        project.framework = "kivy"
                        project.project_type = "desktop"
                        project.start_command = "python main.py"
                        project.health_method = "process"
                        project.screenshot_capable = True
                except Exception:
                    pass

        # Web: Go
        if not project.framework and (root / "go.mod").exists():
            project.framework = "go"
            project.project_type = "web"
            project.start_command = "go run ."
            project.health_method = "http"
            project.port = 8080

        # Web: Rust
        if not project.framework and (root / "Cargo.toml").exists():
            try:
                cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
                if "actix-web" in cargo or "axum" in cargo or "warp" in cargo or "rocket" in cargo:
                    project.framework = "rust-web"
                    project.project_type = "web"
                    project.start_command = "cargo run"
                    project.health_method = "http"
                    project.port = 8080
                elif "tauri" in cargo:
                    project.framework = "tauri"
                    project.project_type = "desktop"
                    project.start_command = "cargo tauri dev"
                    project.health_method = "process"
                    project.screenshot_capable = True
            except Exception:
                pass

        # Desktop: Python GUI
        if not project.framework:
            for f in ["main.py", "app.py", "gui.py"]:
                if (root / f).exists():
                    try:
                        content = (root / f).read_text(encoding="utf-8", errors="ignore")
                        if any(kw in content for kw in ["PyQt", "PySide", "tkinter", "tkinter.ttk", "wx."]):
                            project.framework = "python-gui"
                            project.project_type = "desktop"
                            project.start_command = f"python {f}"
                            project.health_method = "process"
                            project.screenshot_capable = True
                            break
                    except Exception:
                        pass

        # Desktop: C#/.NET
        if not project.framework:
            csproj_files = list(root.glob("*.csproj")) + list(root.glob("**/*.csproj"))
            if csproj_files:
                try:
                    content = csproj_files[0].read_text(encoding="utf-8", errors="ignore")
                    if "Microsoft.NET.Sdk.Web" in content:
                        project.framework = "aspnet"
                        project.project_type = "web"
                        project.start_command = "dotnet run"
                        project.health_method = "http"
                        project.port = 5000
                    elif any(kw in content for kw in ["WPF", "WindowsBase", "PresentationCore", "Avalonia"]):
                        project.framework = "dotnet-gui"
                        project.project_type = "desktop"
                        project.start_command = "dotnet run"
                        project.health_method = "process"
                        project.screenshot_capable = True
                except Exception:
                    pass

        # Java: Spring Boot
        if not project.framework:
            if (root / "pom.xml").exists() or (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
                project.framework = "spring"
                project.project_type = "web"
                if (root / "mvnw").exists():
                    project.start_command = "./mvnw spring-boot:run"
                elif (root / "gradlew").exists():
                    project.start_command = "./gradlew bootRun"
                else:
                    project.start_command = "mvn spring-boot:run"
                project.health_method = "http"
                project.port = 8080

        # PHP: Laravel/Symfony
        if not project.framework and (root / "artisan").exists():
            project.framework = "laravel"
            project.project_type = "web"
            project.start_command = "php artisan serve --host=127.0.0.1 --port={port}"
            project.health_method = "http"
            project.port = 8000

        # PHP: Generic
        if not project.framework and (root / "composer.json").exists():
            project.framework = "php"
            project.project_type = "web"
            project.start_command = "php -S 127.0.0.1:{port}"
            project.health_method = "http"
            project.port = 8000

        # Ruby: Rails
        if not project.framework and (root / "Gemfile").exists():
            try:
                content = (root / "Gemfile").read_text(encoding="utf-8")
                if "rails" in content:
                    project.framework = "rails"
                    project.project_type = "web"
                    project.start_command = "rails s -b 127.0.0.1 -p {port}"
                    project.health_method = "http"
                    project.port = 3000
            except Exception:
                pass

        # CLI tools detection
        if not project.framework:
            for f in ["cli.py", "main.py", "run.py"]:
                if (root / f).exists():
                    try:
                        content = (root / f).read_text(encoding="utf-8", errors="ignore")
                        if any(kw in content for kw in ["click.", "argparse", "typer", "fire.Fire"]):
                            project.framework = "cli"
                            project.project_type = "cli"
                            project.start_command = f"python {f}"
                            project.health_method = "stdout"
                            break
                    except Exception:
                        pass

        # Fallback: generic web on common ports
        if not project.framework:
            project.project_type = "web"
            project.framework = "unknown"
            project.start_command = "npm run dev"
            project.health_method = "http"
            project.port = 3000

        return project

    @staticmethod
    def _extract_port(cmd: str) -> int | None:
        """Extract port from command like '--port 3000' or '-p 3000'."""
        if not cmd:
            return None
        match = re.search(r'[-\-]p(?:ort)?\s+(\d+)', cmd)
        if match:
            return int(match.group(1))
        match = re.search(r'--port\s+(\d+)', cmd)
        if match:
            return int(match.group(1))
        return None


class AppLauncher:
    """Launches the detected app and returns an AppTarget."""

    def __init__(self, root: Path):
        self.root = root
        self.project = FrameworkDetector.detect(root)

    def launch(self, port: int | None = None) -> AppTarget:
        """Launch the app and return the target."""
        if self.project.health_method == "http":
            return self._launch_http(port)
        elif self.project.health_method == "process":
            return self._launch_process()
        elif self.project.health_method == "stdout":
            return self._launch_cli()
        else:
            return self._launch_fallback(port)

    def _launch_http(self, port: int | None = None) -> AppTarget:
        """Launch a web app that serves HTTP."""
        target_port = port or self.project.port or self._find_free_port()

        # Substitute port in command
        cmd = self.project.start_command or "npm run dev"
        cmd = cmd.replace("{port}", str(target_port)).replace("{PORT}", str(target_port))

        # Set up environment
        env = os.environ.copy()
        env.update(self.project.env)
        env["PORT"] = str(target_port)

        # Start process
        working_dir = self.project.working_dir or self.root
        process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=working_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        # Wait for health
        target = AppTarget(
            type="http",
            url=f"http://127.0.0.1:{target_port}",
            pid=process.pid,
            screenshot_mode="playwright",
            process=process,
            port=target_port,
        )

        # Wait for health
        for _ in range(30):
            time.sleep(1)
            if target.is_running():
                break
        else:
            _log.warning("App didn't become healthy in time")

        return target

    def _launch_process(self) -> AppTarget:
        """Launch a desktop app that runs as a process."""
        cmd = self.project.start_command or "python main.py"

        env = os.environ.copy()
        env.update(self.project.env)

        # For desktop apps, we may need special handling
        if sys.platform == "win32":
            # On Windows, use CREATE_NEW_CONSOLE for GUI apps
            creation_flags = subprocess.CREATE_NEW_CONSOLE
        else:
            creation_flags = 0

        process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=self.project.working_dir or self.root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        target = AppTarget(
            type="desktop",
            pid=process.pid,
            screenshot_mode="os",
            process=process,
        )

        # Give it a moment to start
        time.sleep(2)

        return target

    def _launch_cli(self) -> AppTarget:
        """Launch a CLI tool."""
        cmd = self.project.start_command or "python main.py"

        process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=self.project.working_dir or self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        target = AppTarget(
            type="cli",
            pid=process.pid,
            screenshot_mode="none",
            process=process,
        )

        return target

    def _launch_fallback(self, port: int | None = None) -> AppTarget:
        """Fallback launch."""
        return self._launch_http(port)

    def _find_free_port(self) -> int:
        """Find a free port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]


@register
class AppDiscoveryAgent(BaseAgent):
    """Universal project detection and launch for testing."""

    group = AgentGroup.TEST
    domain = AgentDomain.TESTING
    name = "AppDiscoveryAgent"
    description = "Detects project type, launches app, returns target for testing (web/desktop/CLI)"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        with trace_agent(self.name, inp.root) as trace:
            _log.info("AppDiscoveryAgent: Detecting project type...")

            # Detect project
            launcher = AppLauncher(inp.root)
            project = launcher.project

            # Check if already running
            target = self._check_existing(project)
            if target:
                _log.info("App already running at %s", target.url)
                result.data["target"] = self._target_to_dict(target)
                result.data["project_type"] = project.project_type
                result.data["framework"] = project.framework
                result.status = AgentStatus.DONE
                trace.metadata["project_type"] = project.project_type
                trace.metadata["framework"] = project.framework
                return

            # Launch the app
            _log.info("AppDiscoveryAgent: Launching %s app (%s)...", project.project_type, project.framework)
            target = launcher.launch()

            # Store target info
            result.data["target"] = self._target_to_dict(target)
            result.data["project_type"] = project.project_type
            result.data["framework"] = project.framework
            result.data["start_command"] = project.start_command
            result.data["screenshot_capable"] = project.screenshot_capable
            result.data["health_method"] = project.health_method

            # Store target in brain/extra for downstream agents
            inp.extra["app_target"] = target

            result.status = AgentStatus.DONE
            trace.metadata["project_type"] = project.project_type
            trace.metadata["framework"] = project.framework
            trace.metadata["target_type"] = target.type

    def _check_existing(self, project: DetectedProject) -> Optional[AppTarget]:
        """Check if app is already running."""
        import socket

        # Try configured port first
        if project.port:
            try:
                with socket.create_connection(("127.0.0.1", project.port), timeout=1):
                    return AppTarget(
                        type="http",
                        url=f"http://127.0.0.1:{project.port}",
                        port=project.port,
                        screenshot_mode="playwright",
                    )
            except (ConnectionRefusedError, OSError):
                pass

        # Try common ports
        ports = [1612, 8000, 3000, 8080, 5000, 4200, 5173, 80]
        for port in ports:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return AppTarget(
                        type="http",
                        url=f"http://127.0.0.1:{port}",
                        port=port,
                        screenshot_mode="playwright",
                    )
            except (ConnectionRefusedError, OSError):
                continue

        return None

    def _target_to_dict(self, target: AppTarget) -> dict:
        return {
            "type": target.type,
            "url": target.url,
            "pid": target.pid,
            "screenshot_mode": target.screenshot_mode,
            "port": target.port,
        }
