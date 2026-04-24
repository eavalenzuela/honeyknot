"""Base protocol handler and per-connection / per-datagram contexts."""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from honeyknot.config import ServiceConfig


@dataclass
class ConnectionContext:
    """Per-connection state passed to a TCP ProtocolHandler.

    The handler owns `state` (a free-form dict) for whatever session tracking
    it needs. `closed` is a flag the handler sets to request the server drop
    the connection after the current callback returns.
    """
    writer: asyncio.StreamWriter
    addr: tuple
    port: int
    request_logger: logging.Logger
    raw_capture: Any  # file-like, may be None if capture disabled
    state: dict = field(default_factory=dict)
    closed: bool = False

    async def send(self, data: bytes) -> None:
        """Write bytes to the peer and flush."""
        if self.writer.is_closing():
            return
        self.writer.write(data)
        await self.writer.drain()

    def close(self) -> None:
        """Mark this connection for shutdown after the current callback."""
        self.closed = True


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

    def send(self, data: bytes) -> None:
        """Emit a response datagram back to the peer."""
        self.transport.sendto(data, self.addr)


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
