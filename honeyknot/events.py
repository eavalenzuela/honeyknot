"""Structured JSONL event log.

A single append-only file at <log_dir>/events.jsonl receives one JSON
object per line per observed event. Schema (required fields):

    ts        ISO-8601 UTC timestamp
    event     one of: connect, close, datagram, analyzer_hit, protocol
    transport "tcp" | "udp"
    port      int (the honeyknot port the event happened on)
    protocol  str (the handler name, e.g. "ssh", "regex", "dns")
    peer      "<ip>:<port>" of the remote party

Event-specific fields are merged into the object. `bytes_in` and
`bytes_out` are byte counts on close; `bytes` is the datagram size on
datagram events; `detail` is a free-form dict for protocol events.

Writes are line-buffered and best-effort — a logging failure must not
interfere with the honeypot's real job.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("honeyknot.events")

DEFAULT_MAX_BYTES = 100 * 1024 * 1024  # 100 MB
DEFAULT_BACKUP_COUNT = 10


class EventSink:
    """Append-only JSONL writer with size-based rotation.

    Access is serialized via a threading.Lock so multiple concurrent
    coroutines can't interleave partial lines. Writes flush on every call.

    When the active file reaches `max_bytes`, it is rotated: events.jsonl
    becomes events.jsonl.1, events.jsonl.1 becomes events.jsonl.2, etc.,
    up to `backup_count` backups. The oldest is deleted.
    """

    def __init__(self, log_dir: str | Path,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 backup_count: int = DEFAULT_BACKUP_COUNT):
        self.path = Path(log_dir) / "events.jsonl"
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fp = self._open()

    def _open(self):
        try:
            return open(self.path, "a", buffering=1, encoding="utf-8")  # noqa: SIM115
        except OSError as e:
            logger.error("Cannot open event log %s: %s", self.path, e)
            return None

    def _rotate_if_needed(self, about_to_write: int) -> None:
        if self.max_bytes <= 0 or self._fp is None:
            return
        try:
            current_size = self._fp.tell()
        except OSError:
            return
        if current_size + about_to_write <= self.max_bytes:
            return
        with contextlib.suppress(OSError):
            self._fp.close()
        self._fp = None
        # Shift .N-1 -> .N, ..., current -> .1
        for i in range(self.backup_count - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{i}")
            dst = self.path.with_suffix(self.path.suffix + f".{i + 1}")
            if src.exists():
                try:
                    os.replace(src, dst)
                except OSError as e:
                    logger.warning("Rotation step %s->%s failed: %s", src, dst, e)
        if self.path.exists():
            try:
                os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))
            except OSError as e:
                logger.warning("Rotation of %s failed: %s", self.path, e)
        # Drop backups beyond the limit
        oldest = self.path.with_suffix(self.path.suffix + f".{self.backup_count + 1}")
        if oldest.exists():
            with contextlib.suppress(OSError):
                oldest.unlink()
        self._fp = self._open()

    def emit(self, event: str, *, transport: str, port: int,
             protocol: str, peer: tuple | None = None,
             **extra: Any) -> None:
        if self._fp is None:
            return
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
            "event": event,
            "transport": transport,
            "port": port,
            "protocol": protocol,
        }
        if peer is not None:
            try:
                record["peer"] = f"{peer[0]}:{peer[1]}"
            except (TypeError, IndexError):
                record["peer"] = str(peer)
        record.update(extra)
        try:
            line = json.dumps(record, default=_json_default, ensure_ascii=False)
        except Exception:
            # Event emission must never take the honeypot down.
            logger.warning("Unserializable event dropped (event=%s)", event)
            return
        encoded = line + "\n"
        with self._lock:
            self._rotate_if_needed(len(encoded.encode("utf-8")))
            if self._fp is None:
                return
            try:
                self._fp.write(encoded)
            except OSError as e:
                logger.error("Event log write failed: %s", e)

    def close(self) -> None:
        with self._lock:
            if self._fp is not None:
                try:
                    self._fp.close()
                finally:
                    self._fp = None


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray)):
        # Prefer short hex for binary snippets.
        return bytes(obj).hex()
    return str(obj)
