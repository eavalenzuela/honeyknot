"""Base protocol handler and per-connection / per-datagram contexts."""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from honeyknot.config import ServiceConfig


@dataclass
class ConnectionContext:
    """Per-connection state passed to a TCP ProtocolHandler.

    The handler owns `state` (a free-form dict) for whatever session tracking
    it needs. `closed` is a flag the handler sets to request the server drop
    the connection after the current callback returns.

    `emit_event` is an optional callback that forwards a protocol-level event
    (name + kwargs) to the JSONL sink. Handlers should use it to record
    high-signal observations like captured creds or issued commands.

    `store_artifact` is an optional callback for *reconstructed* payloads —
    a file rebuilt from an echo-loader, a heredoc script, an FTP upload
    body. The raw session capture already holds those bytes, but tangled up
    with protocol framing; an artifact is the extracted file on its own, so
    it hashes to the same digest as the identical sample dropped over a
    different transport.
    """
    writer: asyncio.StreamWriter
    addr: tuple
    port: int
    request_logger: logging.Logger
    raw_capture: Any  # file-like, may be None if capture disabled
    pcap_writer: Any = None  # honeyknot.pcap.PcapngWriter or None
    emit_event: Callable[..., None] | None = None
    store_artifact: Callable[..., Any] | None = None
    state: dict = field(default_factory=dict)
    closed: bool = False

    async def send(self, data: bytes) -> None:
        """Write bytes to the peer and flush.

        A peer that hangs up mid-write is the normal case for a honeypot —
        scanners disconnect the instant they have what they came for — so a
        reset is treated as "this connection is over", not as an error. If
        it propagated, every abandoned session would log a traceback.
        """
        if self.writer.is_closing() or self.closed:
            return
        if self.pcap_writer is not None:
            self.pcap_writer.write_outbound(data)
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            self.closed = True

    def close(self) -> None:
        """Mark this connection for shutdown after the current callback."""
        self.closed = True

    def event(self, name: str, **fields: Any) -> None:
        """Emit a protocol-level event. No-op if no sink is wired.

        `name` is positional and the sink supplies `transport`, `port`,
        `protocol`, and `peer` itself — passing any of those five as a field
        raises TypeError at emit time. Pick a different field name.
        """
        if self.emit_event is not None:
            self.emit_event(name, **fields)

    def artifact(self, name: str, data: bytes, *, kind: str = "upload") -> str | None:
        """Hand a reconstructed file to the sample store.

        Returns the SHA-256 hex digest, or None if no store is wired. The
        artifact goes through the same analyze / IOC / YARA / exploit
        pipeline as a session capture.
        """
        if self.store_artifact is None or not data:
            return None
        return self.store_artifact(name=name, data=data, kind=kind)


@dataclass
class DatagramContext:
    """Per-datagram context passed to a UDP ProtocolHandler.

    UDP is stateless; there is no close and no persistent state dict. The
    handler sends zero or more response datagrams via `send` and the server
    handles capture around the callback.
    """
    transport: asyncio.DatagramTransport
    addr: tuple
    port: int
    request_logger: logging.Logger
    emit_event: Callable[..., None] | None = None
    store_artifact: Callable[..., Any] | None = None

    def send(self, data: bytes) -> None:
        """Emit a response datagram back to the peer."""
        self.transport.sendto(data, self.addr)

    def event(self, name: str, **fields: Any) -> None:
        """Emit a protocol-level event. `name` plus `transport`, `port`,
        `protocol`, and `peer` are reserved by the sink — don't pass them
        as fields."""
        if self.emit_event is not None:
            self.emit_event(name, **fields)

    def artifact(self, name: str, data: bytes, *, kind: str = "upload") -> str | None:
        """Hand a reconstructed file to the sample store. See ConnectionContext."""
        if self.store_artifact is None or not data:
            return None
        return self.store_artifact(name=name, data=data, kind=kind)


class ProtocolHandler:
    """Base class for per-port protocol implementations.

    A single handler instance is constructed per port at startup and handles
    every connection on that port. Any per-connection state must live on the
    provided `ConnectionContext`, not on `self`.

    Lifecycle:
      1. `on_connect` runs immediately after the socket is accepted.
         Server-greets-first protocols send their banner here.
      2. `on_data` runs for every chunk read from the peer, in order.
      3. `on_close` runs exactly once when the connection is torn down.

    Handlers may call `ctx.close()` at any point to request shutdown after
    the current callback returns.
    """

    def __init__(self, config: ServiceConfig):
        self.config = config

    async def on_connect(self, ctx: ConnectionContext) -> None:
        """Called once when a client connects. Default: no-op."""
        return None

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        """Called for each chunk of client data. Default: no-op."""
        return None

    async def on_close(self, ctx: ConnectionContext) -> None:
        """Called once when the connection ends. Default: no-op."""
        return None

    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        """Called once per UDP datagram. Default: no-op."""
        return None
