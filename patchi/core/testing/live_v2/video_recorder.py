"""
Video Recorder — Records test sessions for debugging and documentation.

Features:
- Full session video recording
- Automatic segmentation by test
- Metadata overlay (timestamps, test names)
- Compression and format options
- Integration with browser pool
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.testing.video_recorder")


@dataclass
class RecordingConfig:
    """Configuration for video recording."""

    output_dir: Path = Path(".patchi/recordings")
    video_size: dict = field(default_factory=lambda: {"width": 1280, "height": 720})
    fps: int = 30
    codec: str = "vp8"  # vp8, h264
    quality: int = 80  # 0-100
    segment_duration: int = 300  # seconds per segment
    include_audio: bool = False
    metadata_overlay: bool = True


@dataclass
class RecordingSegment:
    """A single recording segment."""

    segment_id: str
    test_name: str
    start_time: float
    end_time: float
    duration_seconds: float
    file_path: Path
    file_size: int
    metadata: dict = field(default_factory=dict)


@dataclass
class TestRecording:
    """Complete recording for a test run."""

    test_run_id: str
    started_at: str
    completed_at: str
    total_duration_seconds: float
    segments: list[RecordingSegment] = field(default_factory=list)
    total_size_bytes: int = 0


class VideoRecorder:
    """
    Records browser test sessions as video.

    Usage:
        recorder = VideoRecorder()

        # Get a browser context with video recording
        context, instance = await recorder.start_recording("test-login")

        # ... run test ...

        # Stop and get recording
        recording = await recorder.stop_recording(context, instance)
    """

    def __init__(self, config: RecordingConfig = None):
        self.config = config or RecordingConfig()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self._active_recordings: dict[str, dict] = {}
        self._playwright = None

    async def start_recording(
        self,
        test_name: str,
        browser_type: str = "chromium",
        headless: bool = True,
    ) -> tuple[Any, Any]:
        """
        Start a new recording session.

        Returns:
            Tuple of (browser_context, browser_instance)
        """
        from playwright.async_api import async_playwright

        if self._playwright is None:
            self._playwright = await async_playwright().start()

        browser_type_obj = getattr(self._playwright, browser_type)
        browser = await browser_type_obj.launch(headless=headless)

        # Create context with video recording
        context = await browser.new_context(
            viewport=self.config.video_size,
            record_video_dir=str(self.config.output_dir / "raw"),
            record_video_size=self.config.video_size,
        )

        recording_id = f"{test_name}-{int(time.time())}"

        self._active_recordings[recording_id] = {
            "test_name": test_name,
            "browser": browser,
            "context": context,
            "start_time": time.time(),
            "segments": [],
            "segment_start": time.time(),
        }

        _log.info(f"Started recording: {recording_id}")
        return context, browser

    async def stop_recording(self, recording_id: str) -> TestRecording:
        """Stop recording and finalize video."""
        if recording_id not in self._active_recordings:
            raise ValueError(f"Recording not found: {recording_id}")

        recording = self._active_recordings.pop(recording_id)
        context = recording["context"]
        browser = recording["browser"]

        # Close context to finalize video
        await context.close()
        await browser.close()

        # Find the video file
        video_dir = self.config.output_dir / "raw"
        video_files = list(video_dir.glob("*.webm"))

        if not video_files:
            _log.warning(f"No video file found for {recording_id}")
            return TestRecording(
                test_run_id=recording_id,
                started_at=datetime.fromtimestamp(
                    recording["start_time"], UTC
                ).isoformat(),
                completed_at=datetime.now(UTC).isoformat(),
                total_duration_seconds=time.time() - recording["start_time"],
            )

        # Get the most recent video file
        video_file = max(video_files, key=lambda f: f.stat().st_mtime)

        # Move to final location
        final_path = self.config.output_dir / f"{recording_id}.webm"
        video_file.rename(final_path)

        duration = time.time() - recording["start_time"]

        segment = RecordingSegment(
            segment_id="1",
            test_name=recording["test_name"],
            start_time=recording["start_time"],
            end_time=time.time(),
            duration_seconds=duration,
            file_path=final_path,
            file_size=final_path.stat().st_size,
        )

        test_recording = TestRecording(
            test_run_id=recording_id,
            started_at=datetime.fromtimestamp(recording["start_time"], UTC).isoformat(),
            completed_at=datetime.now(UTC).isoformat(),
            total_duration_seconds=duration,
            segments=[segment],
            total_size_bytes=segment.file_size,
        )

        _log.info(
            f"Recording saved: {final_path} ({duration:.1f}s, {segment.file_size / 1024:.1f} KB)"
        )
        return test_recording

    async def add_metadata_marker(self, recording_id: str, marker: str, data: dict = None):
        """Add a metadata marker to the current recording."""
        if recording_id in self._active_recordings:
            recording = self._active_recordings[recording_id]
            recording["segments"].append(
                {
                    "marker": marker,
                    "data": data or {},
                    "timestamp": time.time(),
                }
            )

    async def get_recording_info(self, recording_id: str) -> dict | None:
        """Get info about an active recording."""
        return self._active_recordings.get(recording_id)

    async def list_recordings(self) -> list[dict]:
        """List all saved recordings."""
        recordings = []
        for video_file in self.config.output_dir.glob("*.webm"):
            stat = video_file.stat()
            recordings.append(
                {
                    "name": video_file.stem,
                    "path": str(video_file),
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime, UTC).isoformat(),
                    "duration_seconds": stat.st_size / (1024 * 100),  # Rough estimate
                }
            )
        return sorted(recordings, key=lambda r: r["created_at"], reverse=True)

    async def cleanup_old(self, max_age_days: int = 7):
        """Remove old recordings."""
        cutoff = time.time() - (max_age_days * 24 * 3600)

        for video_file in self.config.output_dir.glob("*.webm"):
            if video_file.stat().st_mtime < cutoff:
                video_file.unlink()
                _log.info(f"Deleted old recording: {video_file}")

        # Also clean raw directory
        raw_dir = self.config.output_dir / "raw"
        if raw_dir.exists():
            for video_file in raw_dir.glob("*.webm"):
                if video_file.stat().st_mtime < cutoff:
                    video_file.unlink()

    async def shutdown(self):
        """Shutdown recorder and cleanup."""
        # Stop all active recordings
        for recording_id in list(self._active_recordings.keys()):
            try:
                await self.stop_recording(recording_id)
            except Exception as e:
                _log.warning(f"Error stopping recording {recording_id}: {e}")

        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


# Integration with browser pool
class RecordingBrowserPool:
    """Browser pool with integrated video recording."""

    def __init__(self, pool, recorder: VideoRecorder):
        self.pool = pool
        self.recorder = recorder

    async def get_page_with_recording(self, test_name: str):
        """Get a page with video recording enabled."""
        # This would create a new context with recording
        # For now, use the pool's recording method
        from patchi.core.testing.live_v2.browser_pool import get_browser_pool

        pool = await get_browser_pool()
        context, instance = await pool.get_browser_for_recording()
        page = await context.new_page()

        return page, context, instance

    async def release_recording(self, context, instance, test_name: str):
        """Release recording context and save video."""
        test_recording = await self.recorder.stop_recording(f"{test_name}-{id(instance)}")

        # Clean up browser instance
        try:
            await instance._browser.close()
        except Exception as _exc:
            _log.warning('release_recording failed: %s', _exc)

        return test_recording


# Convenience function
async def record_test_session(
    test_name: str,
    test_func: callable,
    base_url: str = None,
    headless: bool = True,
) -> TestRecording:
    """Record a complete test session."""
    recorder = VideoRecorder()
    context, browser = await recorder.start_recording(test_name, headless=headless)
    page = await context.new_page()

    try:
        if base_url:
            await page.goto(base_url)
        await test_func(page)
    finally:
        recording = await recorder.stop_recording(f"{test_name}-{int(time.time())}")
        await recorder.shutdown()

    return recording
