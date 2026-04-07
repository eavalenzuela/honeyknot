"""Concurrency management: per-port servers and the top-level daemon."""

import logging
import multiprocessing
import signal
import socket
import ssl
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from honeyknot.analyzer import analyze_payload
from honeyknot.config import ServiceConfig, load_all_handlers
from honeyknot.handler import match_request
from honeyknot.logger import get_port_logger, setup_logging

logger = logging.getLogger("honeyknot.server")


class PortServer:
    """Manages a single honeypot port: socket, accept loop, and thread pool."""

    def __init__(self, config: ServiceConfig, bind_ip: str, log_dir: str,
                 thread_count: int, shutdown_event):
        self.config = config
        self.bind_ip = bind_ip
        self.log_dir = log_dir
        self.thread_count = thread_count
        self.shutdown_event = shutdown_event
        self.logger = logging.getLogger(f"honeyknot.server.port.{config.port}")
        self.request_logger = get_port_logger(config.port, log_dir)

    def run(self):
        """Bind socket and enter the accept loop. Blocks until shutdown."""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.settimeout(1.0)
            server_sock.bind((self.bind_ip, self.config.port))
            server_sock.listen(5)
        except OSError as e:
            self.logger.error("Failed to bind port %d: %s", self.config.port, e)
            return

        # Wrap with TLS if configured
        if self.config.service_type == "https":
            if not self.config.tls_certfile or not self.config.tls_keyfile:
                self.logger.error("HTTPS service on port %d requires "
                                  "tls.certfile and tls.keyfile",
                                  self.config.port)
                server_sock.close()
                return
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.config.tls_certfile,
                                self.config.tls_keyfile)
            server_sock = ctx.wrap_socket(server_sock, server_side=True)

        self.logger.info("Listening on %s:%d (%s)",
                         self.bind_ip, self.config.port,
                         self.config.service_type)

        with ThreadPoolExecutor(max_workers=self.thread_count) as pool:
            while not self.shutdown_event.is_set():
                try:
                    conn, addr = server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                self.logger.info("Connection from %s on port %d",
                                 addr, self.config.port)
                pool.submit(self._handle_connection, conn, addr)

        server_sock.close()
        self.logger.info("Port %d shut down", self.config.port)

    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle a single client connection: recv, log, match, respond."""
        try:
            data = conn.recv(4096)
            if not data:
                return

            # Log raw request
            self.request_logger.info("%s: %s", addr, data)

            # Match and respond
            response = match_request(self.config, data)
            if response:
                conn.sendall(response)

            # Analyze payload for file signatures (POST/PUT bodies)
            self._try_analyze(data, addr)

        except Exception:
            self.logger.exception("Error handling connection from %s", addr)
        finally:
            conn.close()

    def _try_analyze(self, data: bytes, addr: tuple):
        """Run file analyzer on request bodies that may contain payloads."""
        try:
            decoded = data.decode("utf-8", errors="replace")
        except Exception:
            return

        # Only analyze POST/PUT requests that have a body
        if not (decoded.startswith("POST ") or decoded.startswith("PUT ")):
            return

        # Extract body after the header/body separator
        separator = b"\r\n\r\n"
        idx = data.find(separator)
        if idx == -1:
            return
        body = data[idx + len(separator):]
        if len(body) < 4:
            return

        result = analyze_payload(body)
        if result:
            self.logger.info("File analysis from %s: %s", addr, result)


def _run_port_server(config: ServiceConfig, bind_ip: str, log_dir: str,
                     thread_count: int, shutdown_event):
    """Top-level function for each port process (must be picklable)."""
    # Re-setup logging in child process
    setup_logging(log_dir)
    server = PortServer(config, bind_ip, log_dir, thread_count, shutdown_event)
    server.run()


class HoneyknotDaemon:
    """Top-level daemon: loads configs, spawns per-port processes, handles signals."""

    def __init__(self, bind_ip: str, handler_dir: str = "handlers/",
                 log_dir: str = "logs/", thread_count: int = 5):
        self.bind_ip = bind_ip
        self.handler_dir = handler_dir
        self.log_dir = log_dir
        self.thread_count = thread_count
        self.shutdown_event = multiprocessing.Event()

    def start(self):
        """Load handler configs, start port processes, and block until shutdown."""
        # Install signal handlers in the main process
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        configs = load_all_handlers(self.handler_dir)
        logger.info("Loaded %d handler config(s)", len(configs))

        with ProcessPoolExecutor(max_workers=len(configs)) as pool:
            futures = {
                pool.submit(
                    _run_port_server,
                    cfg, self.bind_ip, self.log_dir,
                    self.thread_count, self.shutdown_event,
                ): cfg
                for cfg in configs
            }

            for future in as_completed(futures):
                cfg = futures[future]
                try:
                    future.result()
                except Exception:
                    logger.exception("Port %d process crashed", cfg.port)

        logger.info("Honeyknot shut down")

    def _handle_signal(self, signum, frame):
        """Signal handler: trigger graceful shutdown."""
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, shutting down...", sig_name)
        self.shutdown_event.set()
