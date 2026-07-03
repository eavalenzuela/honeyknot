"""Asyncio-based concurrency: one event loop, many listeners, per-port handlers."""

import asyncio
import contextlib
import logging
import os
import signal
import ssl
from datetime import UTC, datetime
from pathlib import Path

from honeyknot.analyzer import scan_payload
from honeyknot.config import ServiceConfig, load_all_handlers
from honeyknot.events import EventSink
from honeyknot.ioc import extract_iocs
from honeyknot.logger import get_port_logger
from honeyknot.metrics import MetricsRegistry, serve_metrics
from honeyknot.pcap import PcapngWriter
from honeyknot.protocols import (
    ConnectionContext,
    DatagramContext,
    ProtocolHandler,
    get_handler,
)
from honeyknot.ratelimit import RateLimiter
from honeyknot.retention import sweep_raw
from honeyknot.samples import SampleStore
from honeyknot.yara_scan import YaraScanner

logger = logging.getLogger("honeyknot.server")

DEFAULT_MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # 10 MB per connection
READ_CHUNK = 65536
ACCEPT_BACKLOG = 128
WRITE_BUFFER_HIGH = 64 * 1024
WRITE_BUFFER_LOW = 16 * 1024
DEFAULT_IDLE_TIMEOUT = 120.0  # seconds a TCP conn may stall before we reap it


def _finalize_payload(*, data: bytes, peer: tuple, transport: str,
                      port: int, protocol: str,
                      events: EventSink | None,
                      samples: SampleStore | None,
                      yara_scanner: YaraScanner | None,
                      logger: logging.Logger) -> str | None:
    """Hash, store, analyze, IOC-extract, YARA-scan, update the sidecar.

    Shared by the TCP capture-close and UDP datagram paths so the two
    transports can never drift. Returns the sha256 hex digest, or None if
    the payload was too small to bother with.
    """
    if len(data) < 4:
        return None

    if events is not None and events.metrics is not None:
        events.metrics.record_bytes(
            len(data), port=port, protocol=protocol, transport=transport,
        )

    digest, is_new, path = (None, False, None)
    if samples is not None:
        digest, is_new, path = samples.store(data)

    result = scan_payload(data)
    if result:
        logger.info("Analyzer hit from %s: %s", peer, result)
        if events is not None:
            events.emit(
                "analyzer_hit", transport=transport, port=port,
                protocol=protocol, peer=peer, sha256=digest, result=result,
            )

    iocs = extract_iocs(data)
    if iocs and events is not None:
        events.emit(
            "ioc", transport=transport, port=port, protocol=protocol,
            peer=peer, sha256=digest, **iocs,
        )

    if is_new and events is not None:
        events.emit(
            "sample_new", transport=transport, port=port, protocol=protocol,
            peer=peer, sha256=digest, bytes=len(data),
        )

    yara_matches: list = []
    if yara_scanner is not None and yara_scanner.enabled:
        yara_matches = yara_scanner.scan(data)
        if yara_matches and events is not None:
            events.emit(
                "yara_match", transport=transport, port=port,
                protocol=protocol, peer=peer, sha256=digest,
                matches=yara_matches,
            )

    if samples is not None and digest is not None and path is not None:
        samples.update_meta(
            digest, size=len(data), peer=peer,
            iocs=iocs, analyzer=result, yara=yara_matches,
        )

    return digest


class PortServer:
    """One TCP listener for a single port, with a per-port protocol handler."""

    def __init__(self, config: ServiceConfig, bind_ip: str, log_dir: str,
                 max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
                 events: EventSink | None = None,
                 samples: SampleStore | None = None,
                 rate_limiter: RateLimiter | None = None,
                 yara_scanner: YaraScanner | None = None,
                 pcap_enabled: bool = False,
                 idle_timeout: float = DEFAULT_IDLE_TIMEOUT):
        self.config = config
        self.bind_ip = bind_ip
        self.log_dir = Path(log_dir)
        self.max_capture_bytes = max_capture_bytes
        self.events = events
        self.samples = samples
        self.rate_limiter = rate_limiter
        self.yara_scanner = yara_scanner
        self.pcap_enabled = pcap_enabled
        self.idle_timeout = idle_timeout
        self.logger = logging.getLogger(f"honeyknot.server.port.{config.port}")
        self.request_logger = get_port_logger(config.port, log_dir)
        self.handler: ProtocolHandler = get_handler(config)
        self._server: asyncio.base_events.Server | None = None
        self._raw_dir = self.log_dir / "raw"
        self._raw_dir.mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        ssl_ctx = self._build_ssl_context()
        if self.config.tls_enabled and ssl_ctx is None:
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

        transport_label = "tls" if self.config.tls_enabled else "tcp"
        self.logger.info("Listening on %s:%d (%s/%s)",
                         self.bind_ip, self.config.port,
                         transport_label, self.config.protocol)

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
        if not self.config.tls_enabled:
            return None
        if not self.config.tls_certfile or not self.config.tls_keyfile:
            self.logger.error("TLS on port %d requires [tls] certfile "
                              "and keyfile", self.config.port)
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(self.config.tls_certfile,
                                self.config.tls_keyfile)
        except (OSError, ssl.SSLError) as e:
            self.logger.error("TLS cert load failed on port %d: %s",
                              self.config.port, e)
            return None
        return ctx

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        peer_ip = peer[0] if peer else "?"

        if self.rate_limiter is not None and not self.rate_limiter.check(peer_ip):
            self.logger.info("Rate-limited %s on port %d", peer, self.config.port)
            self._emit("rate_limited", peer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        self.logger.info("Connection from %s on port %d", peer, self.config.port)

        # Bound asyncio's write buffer so a slow/silent reader can't
        # grow it unbounded and OOM us.
        with contextlib.suppress(AttributeError, NotImplementedError):
            writer.transport.set_write_buffer_limits(
                high=WRITE_BUFFER_HIGH, low=WRITE_BUFFER_LOW,
            )

        capture_path, capture_file = self._open_capture(peer)
        captured = bytearray()
        pcap_writer = self._open_pcap(peer) if self.pcap_enabled else None

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
            pcap_writer=pcap_writer,
            emit_event=_emit_protocol,
        )

        self._emit("connect", peer, capture=str(capture_path) if capture_path else None)

        total = 0
        try:
            await self.handler.on_connect(ctx)

            while not ctx.closed:
                try:
                    if self.idle_timeout and self.idle_timeout > 0:
                        data = await asyncio.wait_for(
                            reader.read(READ_CHUNK), timeout=self.idle_timeout,
                        )
                    else:
                        data = await reader.read(READ_CHUNK)
                except (ConnectionResetError, BrokenPipeError):
                    break
                except TimeoutError:
                    self.logger.debug("Idle timeout (%.0fs) for %s on port %d",
                                      self.idle_timeout, peer, self.config.port)
                    break
                if not data:
                    break

                remaining = self.max_capture_bytes - total
                if remaining > 0:
                    if capture_file is not None:
                        capture_file.write(data[:remaining])
                    captured.extend(data[:remaining])
                    if pcap_writer is not None:
                        pcap_writer.write_inbound(data[:remaining])
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
            if pcap_writer is not None:
                pcap_writer.close()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            digest = self._finalize_capture(bytes(captured), peer)
            self._emit("close", peer, bytes_in=total, sha256=digest)

    def _open_pcap(self, peer: tuple):
        pcap_dir = self.log_dir / "pcap"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        host = peer[0] if peer else "unknown"
        safe_host = host.replace(":", "_").replace("/", "_")
        path = pcap_dir / f"{ts}_{safe_host}_{self.config.port}.pcapng"
        writer = PcapngWriter(path, peer, self.bind_ip, self.config.port)
        if not writer.open:
            return None
        return writer

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
        return _finalize_payload(
            data=data, peer=peer, transport="tcp",
            port=self.config.port, protocol=self.config.protocol,
            events=self.events, samples=self.samples,
            yara_scanner=self.yara_scanner, logger=self.logger,
        )


class _UdpProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that bridges datagrams into a ProtocolHandler."""

    def __init__(self, owner: "UdpPortServer"):
        self.owner = owner
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        peer_ip = addr[0] if addr else "?"
        if (self.owner.rate_limiter is not None
                and not self.owner.rate_limiter.check(peer_ip)):
            self.owner.logger.info("Rate-limited datagram from %s on port %d",
                                   addr, self.owner.config.port)
            self.owner._emit("rate_limited", addr)
            return

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
                 samples: SampleStore | None = None,
                 rate_limiter: RateLimiter | None = None,
                 yara_scanner: YaraScanner | None = None):
        self.config = config
        self.bind_ip = bind_ip
        self.log_dir = Path(log_dir)
        self.events = events
        self.samples = samples
        self.rate_limiter = rate_limiter
        self.yara_scanner = yara_scanner
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
        return _finalize_payload(
            data=data, peer=peer, transport="udp",
            port=self.config.port, protocol=self.config.protocol,
            events=self.events, samples=self.samples,
            yara_scanner=self.yara_scanner, logger=self.logger,
        )


class HoneyknotDaemon:
    """Top-level daemon: loads configs, runs all port listeners on one event loop."""

    def __init__(self, bind_ip: str, handler_dir: str = "handlers/",
                 log_dir: str = "logs/", thread_count: int = 5,
                 max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
                 event_log_max_bytes: int | None = None,
                 event_log_backups: int | None = None,
                 rate_limit_capacity: float = 20.0,
                 rate_limit_refill_per_sec: float = 5.0,
                 run_as_user: str | None = None,
                 run_as_group: str | None = None,
                 yara_rules: str | None = None,
                 pcap_enabled: bool = False,
                 metrics_bind: str | None = None,
                 raw_dir_max_bytes: int = 0,
                 conn_idle_timeout: float = DEFAULT_IDLE_TIMEOUT):
        self.bind_ip = bind_ip
        self.handler_dir = handler_dir
        self.log_dir = log_dir
        # thread_count is accepted for CLI compatibility; asyncio doesn't use it.
        self.thread_count = thread_count
        self.max_capture_bytes = max_capture_bytes
        self.event_log_max_bytes = event_log_max_bytes
        self.event_log_backups = event_log_backups
        self.rate_limit_capacity = rate_limit_capacity
        self.rate_limit_refill_per_sec = rate_limit_refill_per_sec
        self.run_as_user = run_as_user
        self.run_as_group = run_as_group
        self.yara_rules = yara_rules
        self.pcap_enabled = pcap_enabled
        self.metrics_bind = metrics_bind
        self.raw_dir_max_bytes = raw_dir_max_bytes
        self.conn_idle_timeout = conn_idle_timeout

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
        metrics = MetricsRegistry()
        metrics.samples_path = Path(self.log_dir) / "samples"
        events = EventSink(self.log_dir, metrics=metrics, **event_kwargs)
        samples = SampleStore(self.log_dir)
        limiter = RateLimiter(
            capacity=self.rate_limit_capacity,
            refill_per_sec=self.rate_limit_refill_per_sec,
        )
        yara_scanner = YaraScanner(self.yara_rules)

        # Keyed by port for hot-reload comparison.
        servers: dict[int, PortServer | UdpPortServer] = {}
        for cfg in configs:
            servers[cfg.port] = self._build_server(
                cfg, events, samples, limiter, yara_scanner,
            )

        await asyncio.gather(*(s.start() for s in servers.values()))

        metrics_server = await serve_metrics(metrics, self.metrics_bind or "")

        # Drop privileges *after* binding, *before* accepting connections.
        self._drop_privileges()

        stop_event = asyncio.Event()
        reload_event = asyncio.Event()
        loop = asyncio.get_running_loop()

        def _request_stop(sig: signal.Signals) -> None:
            logger.info("Received %s, shutting down...", sig.name)
            stop_event.set()

        def _request_reload() -> None:
            logger.info("Received SIGHUP, scheduling handler reload")
            reload_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _request_stop, sig)
            except NotImplementedError:
                # Windows fallback; not our primary target but harmless.
                signal.signal(sig, lambda s, f: stop_event.set())

        with contextlib.suppress(AttributeError, NotImplementedError,
                                 ValueError):
            loop.add_signal_handler(signal.SIGHUP, _request_reload)

        supervisors: dict[int, asyncio.Task] = {
            port: asyncio.create_task(_supervise(s, events, stop_event))
            for port, s in servers.items()
        }

        async def _reload_loop():
            while not stop_event.is_set():
                await reload_event.wait()
                if stop_event.is_set():
                    return
                reload_event.clear()
                await self._reload_handlers(
                    servers, supervisors, events, samples, limiter,
                    yara_scanner, stop_event,
                )

        reload_task = asyncio.create_task(_reload_loop())

        retention_task: asyncio.Task | None = None
        if self.raw_dir_max_bytes > 0:
            retention_task = asyncio.create_task(sweep_raw(
                Path(self.log_dir) / "raw",
                self.raw_dir_max_bytes,
                stop_event=stop_event,
                events=events,
            ))

        await stop_event.wait()
        reload_event.set()  # wake the reload loop so it exits
        reload_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reload_task
        if retention_task is not None:
            retention_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await retention_task

        for t in supervisors.values():
            t.cancel()
        await asyncio.gather(*(s.stop() for s in servers.values()),
                             return_exceptions=True)
        await asyncio.gather(*supervisors.values(), return_exceptions=True)

        if metrics_server is not None:
            metrics_server.close()
            await metrics_server.wait_closed()

        events.close()
        logger.info("Honeyknot shut down")

    def _build_server(self, cfg, events, samples, limiter, yara_scanner):
        if cfg.transport == "udp":
            return UdpPortServer(
                cfg, self.bind_ip, self.log_dir, events, samples,
                limiter, yara_scanner,
            )
        return PortServer(
            cfg, self.bind_ip, self.log_dir,
            self.max_capture_bytes, events, samples,
            limiter, yara_scanner, pcap_enabled=self.pcap_enabled,
            idle_timeout=self.conn_idle_timeout,
        )

    async def _reload_handlers(self, servers, supervisors, events, samples,
                               limiter, yara_scanner, stop_event):
        """Diff the handler directory against the live set and reconcile.

        Changed configs and removed ports stop; new ports start. Unchanged
        configs (same TOML content) are left running so their rate-limit
        buckets and in-flight connections survive the reload.
        """
        try:
            new_configs = load_all_handlers(self.handler_dir)
        except (FileNotFoundError, ValueError) as e:
            logger.error("reload failed: %s", e)
            if events is not None:
                events.emit("config_reload", transport="-", port=0,
                            protocol="-", error=repr(e))
            return

        new_by_port = {cfg.port: cfg for cfg in new_configs}
        added: list[int] = []
        removed: list[int] = []
        changed: list[int] = []

        for port in list(servers.keys()):
            if port not in new_by_port:
                removed.append(port)
                continue
            if _config_signature(new_by_port[port]) != \
                    _config_signature(servers[port].config):
                changed.append(port)

        for port in new_by_port:
            if port not in servers:
                added.append(port)

        # Stop removed + changed listeners.
        for port in removed + changed:
            supervisors[port].cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await supervisors[port]
            with contextlib.suppress(Exception):
                await servers[port].stop()
            supervisors.pop(port, None)
            servers.pop(port, None)

        # Start new and changed listeners.
        for port in added + changed:
            cfg = new_by_port[port]
            srv = self._build_server(cfg, events, samples, limiter, yara_scanner)
            await srv.start()
            servers[port] = srv
            supervisors[port] = asyncio.create_task(
                _supervise(srv, events, stop_event),
            )

        logger.info("Config reload: +%d / -%d / ~%d",
                    len(added), len(removed), len(changed))
        if events is not None:
            events.emit(
                "config_reload", transport="-", port=0, protocol="-",
                added=added, removed=removed, changed=changed,
            )

    def _drop_privileges(self) -> None:
        """Switch to an unprivileged user after sockets are bound.

        No-op on non-POSIX systems, when not running as root, or when
        neither --run-as-user nor --run-as-group is set.
        """
        if self.run_as_user is None and self.run_as_group is None:
            return
        if os.geteuid() != 0:
            logger.warning("Not running as root; --run-as-user/--run-as-group "
                           "ignored")
            return
        # POSIX-only — import lazily so Windows doesn't break at import time
        import grp
        import pwd

        gid = None
        if self.run_as_group is not None:
            gid = grp.getgrnam(self.run_as_group).gr_gid
        uid = None
        user_gid = None
        if self.run_as_user is not None:
            pw = pwd.getpwnam(self.run_as_user)
            uid = pw.pw_uid
            user_gid = pw.pw_gid

        # Order matters: drop groups first, then setgid, then setuid.
        if uid is not None:
            try:
                os.setgroups([])
            except (OSError, PermissionError) as e:
                logger.warning("setgroups([]) failed: %s", e)
        effective_gid = gid if gid is not None else user_gid
        if effective_gid is not None:
            os.setgid(effective_gid)
        if uid is not None:
            os.setuid(uid)

        logger.info("Dropped privileges to uid=%s gid=%s", uid, effective_gid)


def _config_signature(cfg) -> tuple:
    """Stable, hashable snapshot of a ServiceConfig for change detection.

    Compiled regex objects don't compare well; use the original patterns.
    """
    return (
        cfg.port, cfg.service_type, cfg.protocol, cfg.transport,
        cfg.encoding, cfg.default_response, cfg.description,
        cfg.tls_enabled, cfg.tls_certfile, cfg.tls_keyfile,
        tuple((r.name, r.pattern.pattern, r.response) for r in cfg.rules),
        None if cfg.response_headers is None else (
            cfg.response_headers.status_line,
            tuple(cfg.response_headers.headers),
        ),
        tuple(sorted(cfg.protocol_opts.items())),
    )


async def _supervise(server, events: EventSink | None,
                     stop_event: asyncio.Event) -> None:
    """Keep a port's serve task alive across unexpected failures.

    On crash we emit `port_down` with the error string, back off (capped
    exponential, 1s → 32s), and re-bind via `server.start()` + resume
    serving. On successful rebind we emit `port_up`. On shutdown
    (stop_event set) we just return.

    Cancellation from the daemon is respected — if we're cancelled while
    backing off or rebinding, we exit cleanly.
    """
    backoff = 1.0
    while not stop_event.is_set():
        serve_task = asyncio.create_task(server.serve())
        try:
            await serve_task
            # Clean return (e.g. stop() called). Exit.
            return
        except asyncio.CancelledError:
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await serve_task
            return
        except Exception as exc:
            logger.error("Port %d serve task crashed: %s",
                         server.config.port, exc)
            if events is not None:
                events.emit(
                    "port_down", transport=server.config.transport,
                    port=server.config.port, protocol=server.config.protocol,
                    error=repr(exc),
                )

        if stop_event.is_set():
            return

        # Back off before re-binding.
        try:
            await asyncio.sleep(backoff)
        except asyncio.CancelledError:
            return
        backoff = min(backoff * 2, 32.0)

        # Attempt to re-bind.
        try:
            await server.start()
        except Exception as exc:
            logger.error("Port %d rebind failed: %s",
                         server.config.port, exc)
            continue
        if events is not None:
            events.emit(
                "port_up", transport=server.config.transport,
                port=server.config.port, protocol=server.config.protocol,
            )
        backoff = 1.0  # reset on successful rebind
