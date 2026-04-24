"""Asyncio-based concurrency: one event loop, many listeners, per-port handlers."""

import asyncio
import logging
import signal
import ssl
from datetime import UTC, datetime
from pathlib import Path

from honeyknot.analyzer import scan_payload
from honeyknot.config import ServiceConfig, load_all_handlers
from honeyknot.events import EventSink
from honeyknot.ioc import extract_iocs
from honeyknot.logger import get_port_logger
from honeyknot.protocols import (
    ConnectionContext,
    DatagramContext,
    ProtocolHandler,
    get_handler,
)
from honeyknot.samples import SampleStore

logger = logging.getLogger("honeyknot.server")

DEFAULT_MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # 10 MB per connection
READ_CHUNK = 65536
ACCEPT_BACKLOG = 128


class PortServer:
    """One TCP listener for a single port, with a per-port protocol handler."""

    def __init__(self, config: ServiceConfig, bind_ip: str, log_dir: str,
                 max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
                 events: EventSink | None = None,
                 samples: SampleStore | None = None):
        self.config = config
        self.bind_ip = bind_ip
        self.log_dir = Path(log_dir)
        self.max_capture_bytes = max_capture_bytes
        self.events = events
        self.samples = samples
        self.logger = logging.getLogger(f"honeyknot.server.port.{config.port}")
        self.request_logger = get_port_logger(config.port, log_dir)
        self.handler: ProtocolHandler = get_handler(config)
        self._server: asyncio.base_events.Server | None = None
        self._raw_dir = self.log_dir / "raw"
        self._raw_dir.mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        ssl_ctx = self._build_ssl_context()
        if self.config.service_type == "https" and ssl_ctx is None:
            return

        try:
            self._server = await asyncio.start_server(
                self._handle_connection,
                host=self.bind_ip,
                port=self.config.port,
                backlog=ACCEPT_BACKLOG,
                ssl=ssl_ctx,
                reuse_address=True,
            )
        except OSError as e:
            self.logger.error("Failed to bind port %d: %s", self.config.port, e)
            return

        self.logger.info("Listening on %s:%d (%s)",
                         self.bind_ip, self.config.port,
                         self.config.service_type)

    async def serve(self) -> None:
        if self._server is None:
            return
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self.logger.info("Port %d shut down", self.config.port)

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        if self.config.service_type != "https":
            return None
        if not self.config.tls_certfile or not self.config.tls_keyfile:
            self.logger.error("HTTPS service on port %d requires "
                              "tls.certfile and tls.keyfile", self.config.port)
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.config.tls_certfile, self.config.tls_keyfile)
        return ctx

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        self.logger.info("Connection from %s on port %d", peer, self.config.port)

        capture_path, capture_file = self._open_capture(peer)
        captured = bytearray()

        def _emit_protocol(name: str, **fields) -> None:
            if self.events is not None:
                self.events.emit(
                    "protocol",
                    transport="tcp",
                    port=self.config.port,
                    protocol=self.config.protocol,
                    peer=peer,
                    name=name,
                    **fields,
                )

        ctx = ConnectionContext(
            writer=writer,
            addr=peer,
            port=self.config.port,
            request_logger=self.request_logger,
            raw_capture=capture_file,
            emit_event=_emit_protocol,
        )

        self._emit("connect", peer, capture=str(capture_path) if capture_path else None)

        total = 0
        try:
            await self.handler.on_connect(ctx)

            while not ctx.closed:
                try:
                    data = await reader.read(READ_CHUNK)
                except (ConnectionResetError, BrokenPipeError):
                    break
                if not data:
                    break

                remaining = self.max_capture_bytes - total
                if remaining > 0:
                    if capture_file is not None:
                        capture_file.write(data[:remaining])
                    captured.extend(data[:remaining])
                total += len(data)

                await self.handler.on_data(data, ctx)

                if total >= self.max_capture_bytes:
                    self.logger.debug("Capture cap reached for %s", peer)
                    break

            await self.handler.on_close(ctx)
        except Exception:
            self.logger.exception("Error handling connection from %s", peer)
        finally:
            if capture_file is not None:
                capture_file.close()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            digest = self._finalize_capture(bytes(captured), peer)
            self._emit("close", peer, bytes_in=total, sha256=digest)

    def _open_capture(self, peer: tuple):
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        host = peer[0] if peer else "unknown"
        safe_host = host.replace(":", "_").replace("/", "_")
        path = self._raw_dir / f"{ts}_{safe_host}_{self.config.port}.bin"
        try:
            return path, open(path, "wb")
        except OSError as e:
            self.logger.error("Cannot open raw capture %s: %s", path, e)
            return None, None

    def _emit(self, event: str, peer: tuple, **extra) -> None:
        if self.events is not None:
            self.events.emit(
                event, transport="tcp", port=self.config.port,
                protocol=self.config.protocol, peer=peer, **extra,
            )

    def _finalize_capture(self, data: bytes, peer: tuple) -> str | None:
        """Hash, store, analyze, IOC-extract. Returns sha256 hex or None."""
        if len(data) < 4:
            return None
        digest, is_new, _path = (None, False, None)
        if self.samples is not None:
            digest, is_new, _path = self.samples.store(data)

        result = scan_payload(data)
        if result:
            self.logger.info("Analyzer hit from %s: %s", peer, result)
            if self.events is not None:
                self.events.emit(
                    "analyzer_hit", transport="tcp", port=self.config.port,
                    protocol=self.config.protocol, peer=peer,
                    sha256=digest, result=result,
                )

        iocs = extract_iocs(data)
        if iocs and self.events is not None:
            self.events.emit(
                "ioc", transport="tcp", port=self.config.port,
                protocol=self.config.protocol, peer=peer,
                sha256=digest, **iocs,
            )

        if is_new and self.events is not None:
            self.events.emit(
                "sample_new", transport="tcp", port=self.config.port,
                protocol=self.config.protocol, peer=peer,
                sha256=digest, bytes=len(data),
            )

        return digest


class _UdpProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that bridges datagrams into a ProtocolHandler."""

    def __init__(self, owner: "UdpPortServer"):
        self.owner = owner
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.owner.logger.info("Datagram from %s on port %d (%d bytes)",
                               addr, self.owner.config.port, len(data))
        capture_path = self.owner._dump_raw(data, addr)

        def _emit_protocol(name: str, **fields) -> None:
            self.owner._emit("protocol", addr, name=name, **fields)

        ctx = DatagramContext(
            transport=self.transport,
            addr=addr,
            port=self.owner.config.port,
            request_logger=self.owner.request_logger,
            emit_event=_emit_protocol,
        )
        digest = self.owner._finalize_datagram(data, addr)
        self.owner._emit("datagram", addr,
                         bytes=len(data),
                         capture=str(capture_path) if capture_path else None,
                         sha256=digest)
        asyncio.ensure_future(self._dispatch(data, ctx))

    async def _dispatch(self, data: bytes, ctx: DatagramContext) -> None:
        try:
            await self.owner.handler.on_datagram(data, ctx)
        except Exception:
            self.owner.logger.exception("Error handling datagram from %s", ctx.addr)


class UdpPortServer:
    """One UDP listener for a single port, sharing the ProtocolHandler contract."""

    def __init__(self, config: ServiceConfig, bind_ip: str, log_dir: str,
                 events: EventSink | None = None,
                 samples: SampleStore | None = None):
        self.config = config
        self.bind_ip = bind_ip
        self.log_dir = Path(log_dir)
        self.events = events
        self.samples = samples
        self.logger = logging.getLogger(f"honeyknot.server.port.{config.port}")
        self.request_logger = get_port_logger(config.port, log_dir)
        self.handler: ProtocolHandler = get_handler(config)
        self._raw_dir = self.log_dir / "raw"
        self._raw_dir.mkdir(parents=True, exist_ok=True)
        self._transport: asyncio.DatagramTransport | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self),
                local_addr=(self.bind_ip, self.config.port),
            )
        except OSError as e:
            self.logger.error("Failed to bind UDP port %d: %s",
                              self.config.port, e)
            return
        self.logger.info("Listening on %s:%d (udp/%s)",
                         self.bind_ip, self.config.port, self.config.protocol)

    async def serve(self) -> None:
        while self._transport is not None and not self._transport.is_closing():
            await asyncio.sleep(3600)

    async def stop(self) -> None:
        if self._transport is None:
            return
        self._transport.close()
        self.logger.info("UDP port %d shut down", self.config.port)

    def _dump_raw(self, data: bytes, addr: tuple):
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        host = addr[0] if addr else "unknown"
        safe_host = host.replace(":", "_").replace("/", "_")
        path = self._raw_dir / f"{ts}_{safe_host}_{self.config.port}_udp.bin"
        try:
            with open(path, "wb") as f:
                f.write(data)
            return path
        except OSError as e:
            self.logger.error("Cannot write UDP capture %s: %s", path, e)
            return None

    def _emit(self, event: str, peer: tuple, **extra) -> None:
        if self.events is not None:
            self.events.emit(
                event, transport="udp", port=self.config.port,
                protocol=self.config.protocol, peer=peer, **extra,
            )

    def _finalize_datagram(self, data: bytes, peer: tuple) -> str | None:
        """Hash, store, analyze, IOC-extract. Returns sha256 hex or None."""
        if len(data) < 4:
            return None
        digest, is_new, _path = (None, False, None)
        if self.samples is not None:
            digest, is_new, _path = self.samples.store(data)

        result = scan_payload(data)
        if result:
            self.logger.info("Analyzer hit from %s: %s", peer, result)
            if self.events is not None:
                self.events.emit(
                    "analyzer_hit", transport="udp", port=self.config.port,
                    protocol=self.config.protocol, peer=peer,
                    sha256=digest, result=result,
                )

        iocs = extract_iocs(data)
        if iocs and self.events is not None:
            self.events.emit(
                "ioc", transport="udp", port=self.config.port,
                protocol=self.config.protocol, peer=peer,
                sha256=digest, **iocs,
            )

        if is_new and self.events is not None:
            self.events.emit(
                "sample_new", transport="udp", port=self.config.port,
                protocol=self.config.protocol, peer=peer,
                sha256=digest, bytes=len(data),
            )

        return digest


class HoneyknotDaemon:
    """Top-level daemon: loads configs, runs all port listeners on one event loop."""

    def __init__(self, bind_ip: str, handler_dir: str = "handlers/",
                 log_dir: str = "logs/", thread_count: int = 5,
                 max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
                 event_log_max_bytes: int | None = None,
                 event_log_backups: int | None = None):
        self.bind_ip = bind_ip
        self.handler_dir = handler_dir
        self.log_dir = log_dir
        # thread_count is accepted for CLI compatibility; asyncio doesn't use it.
        self.thread_count = thread_count
        self.max_capture_bytes = max_capture_bytes
        self.event_log_max_bytes = event_log_max_bytes
        self.event_log_backups = event_log_backups

    def start(self) -> None:
        asyncio.run(self._run())

    async def _run(self) -> None:
        configs = load_all_handlers(self.handler_dir)
        logger.info("Loaded %d handler config(s)", len(configs))

        event_kwargs = {}
        if self.event_log_max_bytes is not None:
            event_kwargs["max_bytes"] = self.event_log_max_bytes
        if self.event_log_backups is not None:
            event_kwargs["backup_count"] = self.event_log_backups
        events = EventSink(self.log_dir, **event_kwargs)
        samples = SampleStore(self.log_dir)

        servers: list = []
        for cfg in configs:
            if cfg.transport == "udp":
                servers.append(UdpPortServer(
                    cfg, self.bind_ip, self.log_dir, events, samples,
                ))
            else:
                servers.append(PortServer(
                    cfg, self.bind_ip, self.log_dir,
                    self.max_capture_bytes, events, samples,
                ))

        await asyncio.gather(*(s.start() for s in servers))

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()

        def _request_stop(sig: signal.Signals) -> None:
            logger.info("Received %s, shutting down...", sig.name)
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _request_stop, sig)
            except NotImplementedError:
                # Windows fallback; not our primary target but harmless.
                signal.signal(sig, lambda s, f: stop_event.set())

        serve_tasks = [asyncio.create_task(s.serve()) for s in servers]
        await stop_event.wait()

        for t in serve_tasks:
            t.cancel()
        await asyncio.gather(*(s.stop() for s in servers), return_exceptions=True)
        await asyncio.gather(*serve_tasks, return_exceptions=True)

        events.close()
        logger.info("Honeyknot shut down")
