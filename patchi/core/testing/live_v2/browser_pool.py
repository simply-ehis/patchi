"""
Browser Pool — Manages browser instances for parallel testing.

Features:
- Pool of reusable browser contexts
- Automatic lifecycle management
- Resource limits (max browsers, max pages per browser)
- Health checks and auto-recovery
- Support for Chrome, Firefox, WebKit
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("patchi.testing.browser_pool")


@dataclass
class BrowserInstance:
    """A single browser instance in the pool."""

    id: str
    browser_type: str  # "chromium", "firefox", "webkit"
    created_at: float
    last_used: float
    page_count: int = 0
    healthy: bool = True
    _browser: Any = None  # Playwright browser
    _context: Any = None  # Browser context


@dataclass
class BrowserConfig:
    """Configuration for browser pool."""

    max_browsers: int = 5
    max_pages_per_browser: int = 10
    browser_type: str = "chromium"  # chromium, firefox, webkit
    headless: bool = True
    viewport: dict = field(default_factory=lambda: {"width": 1280, "height": 720})
    default_timeout: int = 30000  # ms
    launch_args: list[str] = field(
        default_factory=lambda: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ]
    )
    # Stealth settings
    stealth: bool = False
    user_agent: str | None = None


class BrowserPool:
    """
    Manages a pool of browser instances for parallel test execution.

    Usage:
        pool = BrowserPool(config)
        await pool.initialize()

        # Get a page for testing
        page = await pool.get_page()
        try:
            await page.goto("https://example.com")
            # ... test actions
        finally:
            await pool.release_page(page)

        await pool.shutdown()
    """

    def __init__(self, config: BrowserConfig = None):
        self.config = config or BrowserConfig()
        self._browsers: dict[str, BrowserInstance] = {}
        self._playwright = None
        self._initialized = False
        self._lock = asyncio.Lock()
        self._stats = {
            "total_created": 0,
            "total_reused": 0,
            "total_failed": 0,
            "current_active": 0,
        }

    async def initialize(self):
        """Initialize the browser pool."""
        if self._initialized:
            return

        try:
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            self._initialized = True
            _log.info(f"Browser pool initialized ({self.config.browser_type})")
        except ImportError:
            _log.error(
                "Playwright not installed. "
                "Install with: pip install playwright && playwright install"
            )
            raise
        except Exception as e:
            _log.error(f"Failed to initialize browser pool: {e}")
            raise

    async def get_page(self) -> Any:
        """Get a browser page from the pool."""
        async with self._lock:
            # Try to reuse existing browser
            for browser in self._browsers.values():
                if browser.healthy and browser.page_count < self.config.max_pages_per_browser:
                    browser.page_count += 1
                    browser.last_used = time.time()
                    self._stats["total_reused"] += 1
                    self._stats["current_active"] += 1
                    return await browser._context.new_page()

            # Create new browser if under limit
            if len(self._browsers) < self.config.max_browsers:
                return await self._create_browser_and_page()

            # Wait for available browser
            while True:
                for browser in self._browsers.values():
                    if browser.healthy and browser.page_count < self.config.max_pages_per_browser:
                        browser.page_count += 1
                        browser.last_used = time.time()
                        self._stats["total_reused"] += 1
                        self._stats["current_active"] += 1
                        return await browser._context.new_page()
                await asyncio.sleep(0.1)

    async def _create_browser_and_page(self) -> Any:
        """Create a new browser instance and return a page."""
        browser_type = getattr(self._playwright, self.config.browser_type)

        # Launch browser
        browser = await browser_type.launch(
            headless=self.config.headless,
            args=self.config.launch_args,
        )

        # Create context
        context = await browser.new_context(
            viewport=self.config.viewport,
            user_agent=self.config.user_agent,
        )

        # Apply stealth if enabled
        if self.config.stealth:
            await self._apply_stealth(context)

        # Create instance record
        instance_id = f"{self.config.browser_type}-{len(self._browsers)}"
        instance = BrowserInstance(
            id=instance_id,
            browser_type=self.config.browser_type,
            created_at=time.time(),
            last_used=time.time(),
            page_count=1,
            _browser=browser,
            _context=context,
        )

        self._browsers[instance_id] = instance
        self._stats["total_created"] += 1
        self._stats["current_active"] += 1

        _log.debug(f"Created new browser: {instance_id}")

        # Return first page
        page = await context.new_page()
        page.set_default_timeout(self.config.default_timeout)
        return page

    async def _apply_stealth(self, context: Any):
        """Apply stealth settings to avoid detection."""
        await context.add_init_script("""
            // Remove webdriver property
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

            // Mock permissions
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );
        """)

    async def release_page(self, page: Any):
        """Release a page back to the pool."""
        async with self._lock:
            self._stats["current_active"] = max(0, self._stats["current_active"] - 1)

            # Find which browser this page belongs to
            for browser in self._browsers.values():
                # This is a simplification - in reality we'd track page->browser mapping
                if browser.page_count > 0:
                    browser.page_count -= 1
                    break

            try:
                await page.close()
            except Exception as e:
                _log.debug(f"Error closing page: {e}")

    async def get_browser_for_recording(self, video_dir: str | None = None) -> tuple[Any, BrowserInstance]:
        """Get a dedicated browser for video recording.

        Args:
            video_dir: Directory to save video recordings.
                       Defaults to .patchi/evidence/video/ if not specified.
        """
        import os
        from pathlib import Path

        async with self._lock:
            # Resolve video directory
            if video_dir is None:
                video_dir = str(Path.cwd() / ".patchi" / "evidence" / "video")
            os.makedirs(video_dir, exist_ok=True)

            # Create a fresh browser for recording
            browser_type = getattr(self._playwright, self.config.browser_type)
            browser = await browser_type.launch(
                headless=self.config.headless,
                args=self.config.launch_args,
            )
            context = await browser.new_context(
                viewport=self.config.viewport,
                record_video_dir=video_dir,
                record_video_size=self.config.viewport,
            )

            instance_id = f"recording-{int(time.time())}"
            instance = BrowserInstance(
                id=instance_id,
                browser_type=self.config.browser_type,
                created_at=time.time(),
                last_used=time.time(),
                page_count=1,
                _browser=browser,
                _context=context,
            )

            self._browsers[instance_id] = instance
            return context, instance

    async def health_check(self) -> dict:
        """Check health of all browsers in pool."""
        healthy = 0
        unhealthy = 0

        for instance in list(self._browsers.values()):
            try:
                # Try to create a test page
                page = await instance._context.new_page()
                await page.close()
                instance.healthy = True
                healthy += 1
            except Exception:
                instance.healthy = False
                unhealthy += 1

        return {
            "total": len(self._browsers),
            "healthy": healthy,
            "unhealthy": unhealthy,
            "stats": self._stats,
        }

    async def cleanup_idle(self, max_idle_seconds: int = 300):
        """Clean up idle browsers."""
        async with self._lock:
            now = time.time()
            to_remove = []

            for instance_id, instance in self._browsers.items():
                if instance.page_count == 0 and (now - instance.last_used) > max_idle_seconds:
                    to_remove.append(instance_id)

            for instance_id in to_remove:
                instance = self._browsers.pop(instance_id)
                try:
                    await instance._context.close()
                    await instance._browser.close()
                except Exception as _exc:
                    _log.warning('cleanup_idle failed: %s', _exc)
                _log.debug(f"Cleaned up idle browser: {instance_id}")

    async def shutdown(self):
        """Shutdown all browsers and playwright."""
        async with self._lock:
            for instance in self._browsers.values():
                try:
                    await instance._context.close()
                    await instance._browser.close()
                except Exception as _exc:
                    _log.warning('shutdown failed: %s', _exc)

            self._browsers.clear()

            if self._playwright:
                await self._playwright.stop()
                self._playwright = None

            self._initialized = False
            _log.info("Browser pool shut down")

    def get_stats(self) -> dict:
        """Get pool statistics."""
        return {
            **self._stats,
            "browser_count": len(self._browsers),
            "config": {
                "max_browsers": self.config.max_browsers,
                "max_pages_per_browser": self.config.max_pages_per_browser,
                "browser_type": self.config.browser_type,
            },
        }


# Global pool instance
_browser_pool: BrowserPool | None = None


async def get_browser_pool(config: BrowserConfig = None) -> BrowserPool:
    """Get or create the global browser pool."""
    global _browser_pool
    if _browser_pool is None or not _browser_pool._initialized:
        _browser_pool = BrowserPool(config)
        await _browser_pool.initialize()
    return _browser_pool


async def shutdown_browser_pool():
    """Shutdown the global browser pool."""
    global _browser_pool
    if _browser_pool:
        await _browser_pool.shutdown()
        _browser_pool = None
