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

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("honeyknot.events")


class EventSink:
    """Append-only JSONL writer, safe across the asyncio event loop.

    Access is serialized via a threading.Lock so multiple concurrent
    coroutines can't interleave partial lines. Writes flush on every call.
    """

    def __init__(self, log_dir: str | Path):
        self.path = Path(log_dir) / "events.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        try:
            self._fp = open(self.path, "a", buffering=1, encoding="utf-8")  # noqa: SIM115
        except OSError as e:
            logger.error("Cannot open event log %s: %s", self.path, e)
            self._fp = None

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
        with self._lock:
            try:
                self._fp.write(line + "\n")
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
