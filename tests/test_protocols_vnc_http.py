"""Tests for VNC and HTTP protocol handlers."""

import asyncio
import logging
import re

import pytest

from honeyknot.config import ResponseHeaders, Rule, ServiceConfig
from honeyknot.protocols import ConnectionContext, HTTPHandler, VNCHandler


class _FakeWriter:
    def __init__(self):
        self.buffer = bytearray()
        self._closing = False

    def is_closing(self):
        return self._closing

    def write(self, data: bytes):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def close(self):
        self._closing = True

    async def wait_closed(self):
        return None


def _ctx(port: int = 0):
    w = _FakeWriter()
    events = []

    def capture(name, **fields):
        events.append((name, fields))

    return ConnectionContext(
        writer=w, addr=("127.0.0.1", 54321), port=port,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=capture,
    ), w, events


def _run(coro):
    return asyncio.run(coro)


def _cfg(protocol: str, **opts) -> ServiceConfig:
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         protocol_opts=opts)


class TestVNC:
    def test_handshake_captures_response(self):
        ctx, writer, events = _ctx()
        handler = VNCHandler(_cfg("vnc"))

        _run(handler.on_connect(ctx))
        assert writer.buffer == b"RFB 003.008\n"
        writer.buffer.clear()

        _run(handler.on_data(b"RFB 003.008\n", ctx))
        assert writer.buffer == bytes([1, 2])  # 1 security type, VNC auth
        writer.buffer.clear()

        _run(handler.on_data(bytes([2]), ctx))  # choose VNC auth
        # 16-byte challenge sent
        assert len(writer.buffer) == 16
        challenge = bytes(writer.buffer)
        writer.buffer.clear()

        response = b"\x11" * 16  # pretend DES response
        _run(handler.on_data(response, ctx))
        # SecurityResult failed + reason
        assert writer.buffer[:4] == b"\x00\x00\x00\x01"
        assert b"Authentication failed" in writer.buffer
        assert ctx.closed

        auth_events = [e for e in events if e[0] == "vnc_auth_attempt"]
        assert len(auth_events) == 1
        assert auth_events[0][1]["challenge"] == challenge
        assert auth_events[0][1]["response"] == response

    def test_rejects_non_vnc_auth_type(self):
        ctx, writer, _ = _ctx()
        handler = VNCHandler(_cfg("vnc"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"RFB 003.008\n", ctx))
        writer.buffer.clear()
        _run(handler.on_data(bytes([1]), ctx))  # None auth
        assert writer.buffer[:4] == b"\x00\x00\x00\x01"
        assert ctx.closed


def _http_cfg():
    rules = [
        Rule(name="php", pattern=re.compile(r"\.php", re.IGNORECASE),
             response="php-hit"),
        Rule(name="post", pattern=re.compile(r"^POST ", re.IGNORECASE),
             response="post-hit"),
    ]
    return ServiceConfig(
        port=80, service_type="http", protocol="http", rules=rules,
        response_headers=ResponseHeaders(
            status_line="HTTP/1.1 200 OK",
            headers=["Content-Type: text/plain", "Connection: close"],
        ),
        default_response="default",
    )


class TestHTTP:
    def test_get_with_rule_match(self):
        ctx, writer, events = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(b"GET /admin.php HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert b"php-hit" in writer.buffer
        assert any(e[0] == "http_request" and e[1]["path"] == "/admin.php"
                   for e in events)

    def test_content_length_body_consumed_even_when_split(self):
        ctx, writer, events = _ctx()
        handler = HTTPHandler(_http_cfg())
        body = b"ELFpayload" * 200  # ~2KB
        req = (b"POST /drop HTTP/1.1\r\nHost: x\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        # Send headers + first half of body, then the rest.
        _run(handler.on_data(req + body[:500], ctx))
        assert writer.buffer == b""  # not complete yet
        _run(handler.on_data(body[500:], ctx))
        assert b"post-hit" in writer.buffer
        http_events = [e for e in events if e[0] == "http_request"]
        assert http_events[0][1]["body_bytes"] == len(body)

    def test_chunked_body_decoded(self):
        ctx, writer, events = _ctx()
        handler = HTTPHandler(_http_cfg())
        # Two chunks: "hello", "world", then final 0 + empty trailer.
        chunked = b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"
        req = (b"POST /x HTTP/1.1\r\nHost: x\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n" + chunked)
        _run(handler.on_data(req, ctx))
        assert b"post-hit" in writer.buffer
        assert events[0][1]["body_bytes"] == 10  # "helloworld"

    def test_oversized_headers_rejected(self):
        ctx, writer, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        huge = b"GET / HTTP/1.1\r\n" + b"X-Pad: " + b"A" * (70 * 1024)
        _run(handler.on_data(huge, ctx))
        assert b"413 Payload Too Large" in writer.buffer
        assert ctx.closed

    def test_connection_close_drops(self):
        ctx, _, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", ctx,
        ))
        assert ctx.closed

    def test_malformed_request_line_400(self):
        ctx, writer, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(b"not-http\r\n\r\n", ctx))
        assert b"400 Bad Request" in writer.buffer
        assert ctx.closed

    def test_pipelined_two_requests(self):
        ctx, writer, events = _ctx()
        handler = HTTPHandler(_http_cfg())
        two = (b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
               b"GET /b.php HTTP/1.1\r\nHost: x\r\n\r\n")
        _run(handler.on_data(two, ctx))
        # Both requests processed
        http_events = [e for e in events if e[0] == "http_request"]
        assert len(http_events) == 2
        assert http_events[0][1]["path"] == "/a"
        assert http_events[1][1]["path"] == "/b.php"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
