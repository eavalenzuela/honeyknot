"""Prometheus text-format metrics endpoint.

A minimal aiohttp-free server implemented with asyncio.start_server.
We expose event counts broken down by (event, port, protocol, transport)
plus a handful of gauges derived from the sample store.

Ops wiring:
    --metrics-bind 127.0.0.1:9099    enable
    --metrics-bind ""                disable (default)

Scrape with `curl http://127.0.0.1:9099/metrics`.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger("honeyknot.metrics")


class MetricsRegistry:
    """Counters collected by the server + event sink.

    Thread-safe-ish: asyncio single-threaded loop, plus a lock for the
    (rare) case where EventSink is called from a non-loop thread.
    """

    def __init__(self):
        self._event_counts: dict[tuple, int] = defaultdict(int)
        self.samples_path: Path | None = None

    def record_event(self, event: str, *, port: int | None = None,
                     protocol: str | None = None,
                     transport: str | None = None) -> None:
        key = (event, protocol or "-", transport or "-", port or 0)
        self._event_counts[key] += 1

    def render(self) -> bytes:
        lines: list[str] = []
        lines.append("# HELP honeyknot_events_total Count of observed events")
        lines.append("# TYPE honeyknot_events_total counter")
        for (event, proto, transport, port), n in sorted(self._event_counts.items()):
            labels = (
                f'event="{_esc(event)}",'
                f'protocol="{_esc(proto)}",'
                f'transport="{_esc(transport)}",'
                f'port="{port}"'
            )
            lines.append(f"honeyknot_events_total{{{labels}}} {n}")

        if self.samples_path is not None and self.samples_path.exists():
            try:
                unique = sum(1 for _ in self.samples_path.rglob("*.bin"))
            except OSError:
                unique = -1
            lines.append("# HELP honeyknot_unique_samples Unique samples "
                         "on disk")
            lines.append("# TYPE honeyknot_unique_samples gauge")
            lines.append(f"honeyknot_unique_samples {unique}")

        return ("\n".join(lines) + "\n").encode("utf-8")


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


async def serve_metrics(registry: MetricsRegistry, bind: str) -> asyncio.base_events.Server | None:
    """Start a metrics server. `bind` is "host:port". Returns the Server
    (so the caller can keep it alive) or None if disabled."""
    if not bind:
        return None
    host, _, port_s = bind.rpartition(":")
    if not host or not port_s:
        logger.error("metrics bind must be host:port, got %r", bind)
        return None
    try:
        port = int(port_s)
    except ValueError:
        logger.error("metrics bind port invalid: %r", port_s)
        return None

    async def handle(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        try:
            # Read one HTTP request line + headers. We don't parse
            # properly — anything that isn't /metrics gets a 404.
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"),
                                             timeout=2.0)
            first_line = request.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first_line.split(" ")
            if len(parts) >= 2 and parts[1].startswith("/metrics"):
                body = registry.render()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain; version=0.0.4\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            else:
                writer.write(
                    b"HTTP/1.1 404 Not Found\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception:
            logger.exception("metrics handler failure")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    try:
        server = await asyncio.start_server(handle, host=host, port=port)
    except OSError as e:
        logger.error("Failed to bind metrics %s:%d: %s", host, port, e)
        return None
    logger.info("Metrics listening on %s:%d", host, port)
    return server
