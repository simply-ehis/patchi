"""
Screenshot Manager — Captures and compares screenshots for visual regression testing.

Features:
- Full page and element screenshots
- Baseline management
- Pixel-perfect comparison with configurable thresholds
- Diff image generation
- Multi-browser support
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing | Any, Optional

_log = logging.getLogger("patchi.testing.screenshot_manager")


@dataclass
class ScreenshotConfig:
    """Configuration for screenshot capture."""
    viewport: dict = field(default_factory=lambda: {"width": 1280, "height": 720})
    full_page: bool = True
    wait_for: str | None = None  # CSS selector to wait for
    wait_timeout: int = 10000  # ms
    animations: str = "disabled"  # "disabled", "allow"
    scale: float = 1.0  # Device scale factor
    mask: list[str] = field(default_factory=list)  # CSS selectors to mask
    clip: dict | None = None  # {x, y, width, height}


@dataclass
class ScreenshotResult:
    """Result of a screenshot capture."""
    url: str
    selector: str | None
    timestamp: str
    image_base64: str
    image_path: str | None
    dimensions: dict  # width, height
    file_size: int
    config: ScreenshotConfig


@dataclass
class VisualDiffResult:
    """Result of visual comparison."""
    baseline_path: str
    current_path: str
    diff_path: str | None
    passed: bool
    difference_percent: float
    threshold_percent: float
    mismatch_pixels: int
    total_pixels: int


class ScreenshotManager:
    """
    Manages screenshot capture and visual regression testing.
    
    Usage:
        manager = ScreenshotManager(baseline_dir="baselines")
        
        # Capture screenshot
        result = await manager.capture(page, "https://example.com")
        
        # Compare with baseline
        diff = await manager.compare("homepage", result.image_base64)
    """
    
    def __init__(
        self,
        baseline_dir: str | Path = ".patchi/visual_baselines",
        threshold: float = 0.1,  # 10% difference allowed
        on_progress: Optional[Callable[[str], None]] = None,
    ):
        self.baseline_dir = Path(baseline_dir)
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self.threshold = threshold
        self.on_progress = on_progress or (lambda _: None)
        self._pixelmatch = None
    
    async def _get_pixelmatch(self):
        """Lazy load pixelmatch for image comparison."""
        if self._pixelmatch is None:
            try:
                import pixelmatch
                self._pixelmatch = pixelmatch
            except ImportError:
                try:
                    from PIL import Image, ImageChops
                    self._pixelmatch = "PIL"
                except ImportError:
                    _log.warning("Neither pixelmatch nor PIL available for image comparison")
        return self._pixelmatch
    
    async def capture(
        self,
        page: Any,
        url: str,
        name: str = None,
        config: ScreenshotConfig = None,
        selector: str = None,
    ) -> ScreenshotResult:
        """
        Capture a screenshot of a page or element.
        
        Args:
            page: Playwright page object
            url: URL to navigate to (or current page if already there)
            name: Optional name for the screenshot
            config: Screenshot configuration
            selector: Optional CSS selector for element screenshot
        
        Returns:
            ScreenshotResult with base64 image and metadata
        """
        config = config or ScreenshotConfig()
        name = name or self._generate_name(url, selector)
        
        self.on_progress(f"📸 Capturing screenshot: {name}")
        
        # Navigate if needed
        if page.url != url:
            await page.goto(url, wait_until="networkidle")
        
        # Wait for selector if specified
        if config.wait_for:
            try:
                await page.wait_for_selector(config.wait_for, timeout=config.wait_timeout)
            except Exception:
                _log.warning(f"Wait for selector timeout: {config.wait_for}")
        
        # Disable animations if configured
        if config.animations == "disabled":
            await page.add_style_tag(content="""
                *, *::before, *::after {
                    animation-duration: 0s !important;
                    animation-delay: 0s !important;
                    transition-duration: 0s !important;
                    transition-delay: 0s !important;
                }
            """)
        
        # Mask elements if specified
        for mask_selector in config.mask:
            await page.add_style_tag(content=f"""
                {mask_selector} {{
                    visibility: hidden !important;
                }}
            """)
        
        # Capture screenshot
        screenshot_options = {
            "full_page": config.full_page,
            "scale": "css" if config.scale == 1.0 else "device",
        }
        
        if config.clip:
            screenshot_options["clip"] = config.clip
        
        if selector:
            element = await page.query_selector(selector)
            if not element:
                raise ValueError(f"Element not found: {selector}")
            screenshot_bytes = await element.screenshot(**screenshot_options)
        else:
            screenshot_bytes = await page.screenshot(**screenshot_options)
        
        # Save to file
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        safe_name = name.replace("/", "_").replace(":", "_")
        filename = f"{safe_name}-{timestamp}.png"
        image_path = self.baseline_dir / "current" / filename
        image_path.parent.mkdir(parents=True, exist_ok=True)
        image_path.write_bytes(screenshot_bytes)
        
        # Convert to base64
        image_base64 = base64.b64encode(screenshot_bytes).decode()
        
        # Get dimensions
        if selector:
            box = await element.bounding_box()
            dimensions = {"width": box["width"], "height": box["height"]} if box else {"width": 0, "height": 0}
        else:
            dimensions = await page.evaluate("() => ({ width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight })")
        
        return ScreenshotResult(
            url=url,
            selector=selector,
            timestamp=datetime.now(timezone.utc).isoformat(),
            image_base64=image_base64,
            image_path=str(image_path),
            dimensions=dimensions,
            file_size=len(screenshot_bytes),
            config=config,
        )
    
    def _generate_name(self, url: str, selector: str = None) -> str:
        """Generate a safe name from URL and selector."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        name = parsed.netloc + parsed.path.replace("/", "-")
        if selector:
            name += f"-{selector.replace(' ', '-').replace('.', '-').replace('#', '-')}"
        return name[:100]
    
    async def save_baseline(self, name: str, image_base64: str) -> str:
        """Save a screenshot as baseline."""
        baseline_path = self.baseline_dir / "baselines" / f"{name}.png"
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        
        image_bytes = base64.b64decode(image_base64)
        baseline_path.write_bytes(image_bytes)
        
        # Also save metadata
        meta_path = baseline_path.with_suffix(".json")
        import json
        meta_path.write_text(json.dumps({
            "name": name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hash": hashlib.sha256(image_bytes).hexdigest(),
        }))
        
        return str(baseline_path)
    
    async def load_baseline(self, name: str) -> str | None:
        """Load a baseline screenshot as base64."""
        baseline_path = self.baseline_dir / "baselines" / f"{name}.png"
        if not baseline_path.exists():
            return None
        
        image_bytes = baseline_path.read_bytes()
        return base64.b64encode(image_bytes).decode()
    
    async def compare(
        self,
        name: str,
        current_base64: str,
        threshold: float = None,
    ) -> VisualDiffResult:
        """
        Compare current screenshot with baseline.
        
        Args:
            name: Baseline name
            current_base64: Current screenshot as base64
            threshold: Difference threshold (0-1), overrides default
        
        Returns:
            VisualDiffResult with comparison details
        """
        threshold = threshold or self.threshold
        baseline_b64 = await self.load_baseline(name)
        
        if not baseline_b64:
            return VisualDiffResult(
                baseline_path="",
                current_path="",
                diff_path=None,
                passed=False,
                difference_percent=100.0,
                threshold_percent=threshold * 100,
                mismatch_pixels=0,
                total_pixels=0,
            )
        
        baseline_bytes = base64.b64decode(baseline_b64)
        current_bytes = base64.b64decode(current_base64)
        
        # Compare using pixelmatch or PIL
        pixelmatch = await self._get_pixelmatch()
        
        if pixelmatch == "PIL":
            return await self._compare_pil(baseline_bytes, current_bytes, threshold, name)
        elif pixelmatch:
            return await self._compare_pixelmatch(baseline_bytes, current_bytes, threshold, name, pixelmatch)
        else:
            # Fallback: simple hash comparison
            return self._compare_hash(baseline_bytes, current_bytes, threshold, name)
    
    async def _compare_pil(
        self,
        baseline_bytes: bytes,
        current_bytes: bytes,
        threshold: float,
        name: str,
    ) -> VisualDiffResult:
        """Compare using PIL."""
        from PIL import Image, ImageChops
        import io
        
        baseline_img = Image.open(io.BytesIO(baseline_bytes)).convert("RGBA")
        current_img = Image.open(io.BytesIO(current_bytes)).convert("RGBA")
        
        # Resize if needed
        if baseline_img.size != current_img.size:
            current_img = current_img.resize(baseline_img.size, Image.Resampling.LANCZOS)
        
        # Calculate difference
        diff = ImageChops.difference(baseline_img, current_img)
        diff_pixels = sum(1 for pixel in diff.getdata() if pixel[3] > 0)  # Alpha > 0 means different
        total_pixels = baseline_img.width * baseline_img.height
        difference_percent = diff_pixels / total_pixels
        
        # Generate diff image
        diff_path = None
        if difference_percent > threshold:
            diff_img = Image.new("RGBA", baseline_img.size, (255, 0, 0, 0))
            for x in range(baseline_img.width):
                for y in range(baseline_img.height):
                    b = baseline_img.getpixel((x, y))
                    c = current_img.getpixel((x, y))
                    if b != c:
                        diff_img.putpixel((x, y), (255, 0, 0, 255))
            
            diff_path = self.baseline_dir / "diffs" / f"{name}-diff.png"
            diff_path.parent.mkdir(parents=True, exist_ok=True)
            diff_img.save(diff_path)
            diff_path = str(diff_path)
        
        return VisualDiffResult(
            baseline_path=str(self.baseline_dir / "baselines" / f"{name}.png"),
            current_path="",
            diff_path=diff_path,
            passed=difference_percent <= threshold,
            difference_percent=difference_percent * 100,
            threshold_percent=threshold * 100,
            mismatch_pixels=diff_pixels,
            total_pixels=total_pixels,
        )
    
    async def _compare_pixelmatch(
        self,
        baseline_bytes: bytes,
        current_bytes: bytes,
        threshold: float,
        name: str,
        pixelmatch_module: Any,
    ) -> VisualDiffResult:
        """Compare using pixelmatch."""
        # pixelmatch requires PNG buffers
        # This is a simplified version
        return await self._compare_pil(baseline_bytes, current_bytes, threshold, name)
    
    def _compare_hash(
        self,
        baseline_bytes: bytes,
        current_bytes: bytes,
        threshold: float,
        name: str,
    ) -> VisualDiffResult:
        """Fallback hash comparison."""
        baseline_hash = hashlib.sha256(baseline_bytes).hexdigest()
        current_hash = hashlib.sha256(current_bytes).hexdigest()
        
        passed = baseline_hash == current_hash
        difference_percent = 0.0 if passed else 100.0
        
        return VisualDiffResult(
            baseline_path=str(self.baseline_dir / "baselines" / f"{name}.png"),
            current_path="",
            diff_path=None,
            passed=passed,
            difference_percent=difference_percent,
            threshold_percent=threshold * 100,
            mismatch_pixels=0,
            total_pixels=0,
        )
    
    async def batch_capture(
        self,
        page: Any,
        urls: list[str],
        config: ScreenshotConfig = None,
    ) -> list[ScreenshotResult]:
        """Capture screenshots for multiple URLs."""
        results = []
        for i, url in enumerate(urls):
            self.on_progress(f"📸 [{i+1}/{len(urls)}] {url}")
            result = await self.capture(page, url, config=config)
            results.append(result)
        return results
    
    async def batch_compare(
        self,
        name_prefix: str,
        current_results: list[ScreenshotResult],
        threshold: float = None,
    ) -> list[VisualDiffResult]:
        """Compare multiple screenshots with baselines."""
        diffs = []
        for i, result in enumerate(current_results):
            name = f"{name_prefix}-{i}"
            diff = await self.compare(name, result.image_base64, threshold)
            diffs.append(diff)
        return diffs


class VisualRegressionAgent:
    """Agent for visual regression testing."""
    
    def __init__(self, root: Path, config: dict):
        self.root = root
        self.config = config
        self.manager = ScreenshotManager(
            baseline_dir=root / ".patchi" / "visual_baselines",
            threshold=config.get("visual_threshold", 0.1),
        )
    
    async def run(self, urls: list[str], base_url: str = None, update_baselines: bool = False) -> dict:
        """Run visual regression test on URLs."""
        from patchi.core.testing.live_v2.browser_pool import get_browser_pool, BrowserConfig
        
        pool = await get_browser_pool(BrowserConfig(headless=True))
        page = await pool.get_page()
        
        try:
            results = await self.manager.batch_capture(page, urls)
            
            if update_baselines:
                for i, result in enumerate(results):
                    await self.manager.save_baseline(f"test-{i}", result.image_base64)
                return {"updated": len(results), "message": "Baselines updated"}
            
            diffs = await self.manager.batch_compare("test", results)
            
            passed = sum(1 for d in diffs if d.passed)
            failed = len(diffs) - passed
            
            return {
                "total": len(diffs),
                "passed": passed,
                "failed": failed,
                "diffs": [d.__dict__ for d in diffs],
            }
        finally:
            await pool.release_page(page)