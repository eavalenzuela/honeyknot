"""Tests for batch-4 protocol handlers: IMAP, POP3, WS-Discovery, S7."""

import asyncio
import base64
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols import (
    ConnectionContext,
    DatagramContext,
    IMAPHandler,
    POP3Handler,
    S7Handler,
    WSDHandler,
)


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


class _FakeTransport:
    def __init__(self):
        self.sent: list[tuple[bytes, tuple]] = []

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append((data, addr))

    def is_closing(self):
        return False

    def close(self):
        pass


def _tcp_ctx():
    w = _FakeWriter()
    events: list = []
    ctx = ConnectionContext(
        writer=w, addr=("127.0.0.1", 54321), port=0,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, w, events


def _udp_ctx():
    t = _FakeTransport()
    events: list = []
    ctx = DatagramContext(
        transport=t, addr=("10.0.0.5", 12345), port=0,
        request_logger=logging.getLogger("test.req"),
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, t, events


def _cfg(protocol, transport="tcp"):
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         transport=transport)


def _run(coro):
    return asyncio.run(coro)


# ---------- IMAP ----------
class TestIMAP:
    def test_greeting_then_login_captures_creds(self):
        ctx, writer, events = _tcp_ctx()
        handler = IMAPHandler(_cfg("imap"))
        _run(handler.on_connect(ctx))
        assert writer.buffer.startswith(b"* OK")
        assert b"AUTH=PLAIN" in writer.buffer
        writer.buffer.clear()

        _run(handler.on_data(b"a1 LOGIN attacker s3cret\r\n", ctx))
        assert b"a1 NO" in writer.buffer
        assert ctx.closed
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "attacker"
        assert creds[0][1]["password"] == "s3cret"

    def test_login_with_quotes(self):
        ctx, writer, events = _tcp_ctx()
        handler = IMAPHandler(_cfg("imap"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b'b2 LOGIN "user@example.com" "pa ss"\r\n', ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "user@example.com"
        assert creds[0][1]["password"] == "pa ss"

    def test_authenticate_plain_captures(self):
        ctx, writer, events = _tcp_ctx()
        handler = IMAPHandler(_cfg("imap"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"c3 AUTHENTICATE PLAIN\r\n", ctx))
        assert b"+ \r\n" in writer.buffer
        writer.buffer.clear()
        blob = base64.b64encode(b"\x00user\x00pw").decode()
        _run(handler.on_data(blob.encode() + b"\r\n", ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "user"
        assert creds[0][1]["password"] == "pw"
        assert ctx.closed

    def test_capability(self):
        ctx, writer, _ = _tcp_ctx()
        handler = IMAPHandler(_cfg("imap"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"d4 CAPABILITY\r\n", ctx))
        assert b"* CAPABILITY" in writer.buffer
        assert b"d4 OK" in writer.buffer


# ---------- POP3 ----------
class TestPOP3:
    def test_apop_timestamp_and_user_pass(self):
        ctx, writer, events = _tcp_ctx()
        handler = POP3Handler(_cfg("pop3"))
        _run(handler.on_connect(ctx))
        # banner should contain an APOP-style timestamp
        assert writer.buffer.startswith(b"+OK")
        assert b"<" in writer.buffer and b">" in writer.buffer
        writer.buffer.clear()

        _run(handler.on_data(b"USER admin\r\nPASS hunter2\r\n", ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "admin"
        assert creds[0][1]["password"] == "hunter2"
        assert b"-ERR" in writer.buffer
        assert ctx.closed

    def test_apop_digest_captured(self):
        ctx, writer, events = _tcp_ctx()
        handler = POP3Handler(_cfg("pop3"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"APOP jdoe deadbeef\r\n", ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["mechanism"] == "APOP"
        assert creds[0][1]["digest"] == "deadbeef"
        assert ctx.closed

    def test_unauth_list_logged(self):
        ctx, writer, events = _tcp_ctx()
        handler = POP3Handler(_cfg("pop3"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"RETR 1\r\n", ctx))
        assert b"-ERR" in writer.buffer
        assert any(e[0] == "pop3_post_auth_attempt" for e in events)


# ---------- WS-Discovery ----------
class TestWSD:
    def test_probe_returns_probematches(self):
        ctx, transport, events = _udp_ctx()
        handler = WSDHandler(_cfg("wsd", transport="udp"))
        probe = (b'<?xml version="1.0" encoding="UTF-8"?>'
                 b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
                 b' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
                 b' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
                 b"<s:Header>"
                 b"<a:Action>"
                 b"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
                 b"</a:Action>"
                 b"<a:MessageID>urn:uuid:abcd</a:MessageID>"
                 b"</s:Header><s:Body/></s:Envelope>")
        # Pad so our reply is smaller
        probe = probe + b"\n" + b"x" * 2000
        _run(handler.on_datagram(probe, ctx))
        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        assert b"ProbeMatches" in reply
        assert b"urn:uuid:abcd" in reply
        # Must be shorter than request (no amplification)
        assert len(reply) < len(probe)
        assert any(e[0] == "wsd_probe" and "Probe" in e[1]["action"]
                   for e in events)

    def test_non_probe_ignored(self):
        ctx, transport, _ = _udp_ctx()
        handler = WSDHandler(_cfg("wsd", transport="udp"))
        _run(handler.on_datagram(
            b"<Envelope><Header><Action>"
            b"http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello"
            b"</Action></Header></Envelope>",
            ctx,
        ))
        assert transport.sent == []


# ---------- S7 ----------
class TestS7:
    def test_cotp_cr_gets_cc(self):
        ctx, writer, _ = _tcp_ctx()
        handler = S7Handler(_cfg("s7"))
        # TPKT(4) + COTP CR: LI=17, code=0xE0, dst-ref=0, src-ref=0x1234, class=0,
        #                    params (14 bytes) — but LI byte value covers the rest
        cotp = (
            bytes([17, 0xE0])
            + b"\x00\x00"
            + b"\x12\x34"
            + b"\x00"
            + b"\xc0\x01\x0a"
            + b"\xc1\x02\x01\x00"
            + b"\xc2\x02\x01\x02"
        )
        frame = struct.pack(">BBH", 3, 0, 4 + len(cotp)) + cotp
        _run(handler.on_data(frame, ctx))

        reply = bytes(writer.buffer)
        assert reply[0] == 3  # TPKT version
        # COTP Connection Confirm code 0xD0 at offset 5
        assert reply[5] == 0xD0
        # CC's dst_ref must echo CR's src_ref (bytes 6-7 of the reply frame).
        assert reply[6:8] == b"\x12\x34"

    def test_setup_comm_ack(self):
        ctx, writer, events = _tcp_ctx()
        handler = S7Handler(_cfg("s7"))

        # First complete the CR/CC handshake
        cr = bytes([17, 0xE0]) + b"\x00\x00\x12\x34\x00" \
            + b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
        _run(handler.on_data(
            struct.pack(">BBH", 3, 0, 4 + len(cr)) + cr, ctx,
        ))
        writer.buffer.clear()

        # Build S7 Setup Communication (function 0xF0)
        params = b"\xf0\x00\x00\x03\x00\x03\x03\xc0"
        s7 = struct.pack(">BBHHHH",
                         0x32, 1, 0, 0x0100, len(params), 0) + params
        # COTP DT header: LI=2, code=0xF0, TPDU number=0x80
        cotp_dt = bytes([2, 0xF0, 0x80])
        tpkt_total = 4 + len(cotp_dt) + len(s7)
        pkt = struct.pack(">BBH", 3, 0, tpkt_total) + cotp_dt + s7
        _run(handler.on_data(pkt, ctx))

        reply = bytes(writer.buffer)
        assert reply[0] == 3
        # Locate S7 protocol id in reply; ROSCTR should be 3 (Ack_Data)
        s7_start = reply.index(b"\x32")
        assert reply[s7_start + 1] == 3
        # Setup Ack function byte (0xF0) present
        assert b"\xf0\x00" in reply[s7_start:]
        assert any(e[0] == "s7_request" and e[1]["function"] == 0xF0
                   for e in events)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
