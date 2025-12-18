import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional


class ProtocolHandler:
    """Interface for protocol specific request handlers."""

    def handle_client(self, client_socket: socket.socket, client_address) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class MetricsClient:
    """Minimal metrics interface allowing dependency injection."""

    def increment(self, name: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class NullMetrics(MetricsClient):
    def increment(self, name: str) -> None:
        return


class ThrottlePolicy:
    def allow(self, client_address) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class NullThrottle(ThrottlePolicy):
    def allow(self, client_address) -> bool:
        return True


class ServiceRunner:
    """Owns socket lifecycle, accepts connections, and dispatches to a handler."""

    def __init__(
        self,
        bind_ip: str,
        port: int,
        handler: ProtocolHandler,
        *,
        backlog: int = 5,
        logger: Optional[logging.Logger] = None,
        metrics: Optional[MetricsClient] = None,
        throttle: Optional[ThrottlePolicy] = None,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = int(port)
        self.handler = handler
        self.backlog = backlog
        self.logger = logger or logging.getLogger(__name__)
        self.metrics = metrics or NullMetrics()
        self.throttle = throttle or NullThrottle()
        self._stop_event = threading.Event()
        self._socket: Optional[socket.socket] = None
        self._last_error: Optional[BaseException] = None

    @property
    def last_error(self) -> Optional[BaseException]:
        return self._last_error

    def stop(self) -> None:
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass

    def _bind_socket(self) -> socket.socket:
        conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conn_sock.bind((self.bind_ip, self.port))
        conn_sock.listen(self.backlog)
        conn_sock.settimeout(1.0)
        return conn_sock

    def run(self) -> None:
        try:
            self._socket = self._bind_socket()
            self.logger.info("Service listening on %s:%s", self.bind_ip, self.port)
            while not self._stop_event.is_set():
                try:
                    client_socket, client_address = self._socket.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    self._last_error = exc
                    raise

                if not self.throttle.allow(client_address):
                    client_socket.close()
                    continue

                self.metrics.increment("connections.accepted")
                try:
                    self.handler.handle_client(client_socket, client_address)
                    self.metrics.increment("connections.handled")
                except BaseException as exc:
                    self.metrics.increment("connections.failed")
                    self._last_error = exc
                    self.logger.exception("Handler failure for %s:%s", self.bind_ip, self.port)
                    raise
        finally:
            if self._socket:
                try:
                    self._socket.close()
                except OSError:
                    pass
            self.logger.info("Service stopped on %s:%s", self.bind_ip, self.port)


class ServiceScheduler:
    """Runs multiple services within a single process using a shared executor."""

    def __init__(self, *, max_workers: Optional[int] = None, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._futures = []
        self._services: Iterable[ServiceRunner] = []

    def start(self, services: Iterable[ServiceRunner]) -> None:
        self._services = list(services)
        for service in self._services:
            self._futures.append(self.executor.submit(service.run))

    def wait(self) -> None:
        try:
            for future in as_completed(self._futures):
                exc = future.exception()
                if exc:
                    self.logger.error("Service failed: %s", exc)
                    self.stop()
                    raise exc
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested. Stopping services...")
            self.stop()
        finally:
            self.executor.shutdown(wait=True)

    def stop(self) -> None:
        for service in self._services:
            service.stop()
