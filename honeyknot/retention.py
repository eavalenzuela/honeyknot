"""Raw-capture retention sweeper.

logs/raw/ grows monotonically: every session gets a new file. This task
runs in the background, totaling the directory's size every `interval`
seconds, and if it exceeds `max_bytes`, deletes oldest files (by mtime)
until the total is back under the cap.

The sample store's content-addressed logs/samples/ holds the unique
payloads; the per-session raw/ files exist only for ordering and
direction awareness. Losing the oldest ones is cheap.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

logger = logging.getLogger("honeyknot.retention")

DEFAULT_INTERVAL = 300.0  # 5 minutes


async def sweep_raw(raw_dir: Path, max_bytes: int,
                    interval: float = DEFAULT_INTERVAL,
                    stop_event: asyncio.Event | None = None,
                    events=None) -> None:
    """Background coroutine. Cancel it on shutdown.

    Emits a `retention_sweep` event after every non-trivial sweep so ops
    can see how much got pruned.
    """
    if max_bytes <= 0:
        return
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            deleted, total_after = _sweep_once(raw_dir, max_bytes)
        except Exception:
            logger.exception("retention sweep failed")
            deleted, total_after = 0, -1
        if deleted > 0 and events is not None:
            events.emit(
                "retention_sweep", transport="-", port=0, protocol="-",
                deleted=deleted, total_bytes=total_after,
            )
        try:
            if stop_event is not None:
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
                    return
                except TimeoutError:
                    pass
            else:
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return


def _sweep_once(raw_dir: Path, max_bytes: int) -> tuple[int, int]:
    """Return (files_deleted, remaining_total_bytes)."""
    if not raw_dir.exists():
        return 0, 0
    entries: list[tuple[float, int, Path]] = []
    total = 0
    for p in raw_dir.iterdir():
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        entries.append((st.st_mtime, st.st_size, p))
        total += st.st_size
    if total <= max_bytes:
        return 0, total
    entries.sort(key=lambda e: e[0])  # oldest first
    deleted = 0
    for mtime, size, path in entries:
        if total <= max_bytes:
            break
        try:
            path.unlink()
        except OSError as e:
            logger.warning("retention unlink %s failed: %s", path, e)
            continue
        total -= size
        deleted += 1
        _ = mtime
    return deleted, total
