"""Protocol handlers for Honeyknot services.

The handlers here translate :class:`service_loader.ServiceDefinition` objects
into runnable protocol implementations that can be used by
``service_runner.ServiceRunner``. Each handler is responsible for:

* Reading request data from the client socket.
* Selecting an appropriate response rule using the service definition.
* Sending a response in the correct format for the protocol.
* Emitting structured JSON logs with request/response metadata.

The module intentionally keeps the protocol surface small to make it easy to
extend with additional protocols or logging sinks later.
"""

from __future__ import annotations

import binascii
import json
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, Tuple

from service_loader import ResponseRule, ServiceDefinition


class BaseServiceHandler:
    """Shared helpers for all protocol handlers."""

    def __init__(
        self,
        service: ServiceDefinition,
        *,
        log_dir: str,
        capture_limit: int,
        log_max_bytes: int,
        log_backup_count: int,
    ) -> None:
        self.service = service
        self.capture_limit = max(0, int(capture_limit))
        self.logger = self._build_logger(
            log_dir, service.port, log_max_bytes, log_backup_count
        )

    def _build_logger(
        self, log_dir: str, port: int, max_bytes: int, backup_count: int
    ) -> logging.Logger:
        logger = logging.getLogger(f"honeyknot.port.{port}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = RotatingFileHandler(
                f"{log_dir}/{port}.log", maxBytes=max_bytes, backupCount=backup_count
            )
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _serialize_capture(self, data: bytes) -> str:
        limited = data[: self.capture_limit] if self.capture_limit else b""
        return binascii.hexlify(limited).decode("ascii")

    def _log_event(
        self,
        client_address: Tuple[str, int],
        matched_rule: Optional[ResponseRule],
        data: bytes,
        *,
        error: Optional[str] = None,
    ) -> None:
        entry = {
            "client_ip": client_address[0],
            "client_port": client_address[1],
            "protocol": self.service.protocol,
            "port": self.service.port,
            "matched_rule": matched_rule.match if matched_rule else None,
            "capture": self._serialize_capture(data),
        }
        if error:
            entry["error"] = error
        self.logger.info(json.dumps(entry))


class TcpServiceHandler(BaseServiceHandler):
    """Simple TCP echo handler using regex-based responses."""

    def handle_client(self, client_socket, client_address) -> None:
        try:
            client_socket.settimeout(10)
            data = client_socket.recv(4096)
            matched_rule = self.service.find_response(data)
            if matched_rule:
                body = matched_rule.body
                payload = (
                    body
                    if isinstance(body, (bytes, bytearray))
                    else body.encode(self.service.encoding)
                )
                client_socket.sendall(payload)
            self._log_event(client_address, matched_rule, data)
        except Exception as exc:  # pragma: no cover - defensive
            self._log_event(client_address, None, b"", error=str(exc))
            raise
        finally:
            try:
                client_socket.close()
            except OSError:
                pass


class HttpServiceHandler(BaseServiceHandler):
    """Minimal HTTP handler that uses service response rules."""

    def handle_client(self, client_socket, client_address) -> None:
        try:
            client_socket.settimeout(10)
            data = client_socket.recv(4096)
            matched_rule = self.service.find_response(data)
            response_body = matched_rule.body if matched_rule else ""
            if not isinstance(response_body, str):
                response_body = response_body.decode(self.service.encoding)

            headers = list(self.service.headers)
            if headers and not any(h.lower().startswith("content-length") for h in headers):
                headers.append(f"Content-Length: {len(response_body)}")
            response = "\r\n".join(headers + ["", response_body])
            client_socket.sendall(response.encode(self.service.encoding))
            self._log_event(client_address, matched_rule, data)
        except Exception as exc:  # pragma: no cover - defensive
            self._log_event(client_address, None, b"", error=str(exc))
            raise
        finally:
            try:
                client_socket.close()
            except OSError:
                pass


def handler_for_service(
    service: ServiceDefinition,
    *,
    log_dir: str,
    capture_limit: int,
    log_max_bytes: int,
    log_backup_count: int,
):
    if service.protocol == "http":
        return HttpServiceHandler(
            service,
            log_dir=log_dir,
            capture_limit=capture_limit,
            log_max_bytes=log_max_bytes,
            log_backup_count=log_backup_count,
        )
    return TcpServiceHandler(
        service,
        log_dir=log_dir,
        capture_limit=capture_limit,
        log_max_bytes=log_max_bytes,
        log_backup_count=log_backup_count,
    )

