"""Tests for batch-3 protocol handlers: SIP, IPMI, CoAP, Modbus, MQTT,
MySQL, Postgres."""

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols import (
    CoAPHandler,
    ConnectionContext,
    DatagramContext,
    IPMIHandler,
    ModbusHandler,
    MQTTHandler,
    MySQLHandler,
    PostgresHandler,
    SIPHandler,
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
        self._closing = False

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append((data, addr))

    def is_closing(self):
        return self._closing

    def close(self):
        self._closing = True


def _tcp_ctx(port: int = 0):
    w = _FakeWriter()
    events: list[tuple[str, dict]] = []

    def capture(name, **fields):
        events.append((name, fields))

    return ConnectionContext(
        writer=w, addr=("127.0.0.1", 54321), port=port,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=capture,
    ), w, events


def _udp_ctx(port: int = 0):
    t = _FakeTransport()
    events: list[tuple[str, dict]] = []

    def capture(name, **fields):
        events.append((name, fields))

    ctx = DatagramContext(
        transport=t,
        addr=("127.0.0.1", 54321),
        port=port,
        request_logger=logging.getLogger("test.req"),
        emit_event=capture,
    )
    return ctx, t, events


def _cfg(protocol, transport="tcp", **opts):
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         transport=transport, protocol_opts=opts)


def _run(coro):
    return asyncio.run(coro)


# ---------- SIP ----------
class TestSIP:
    def test_options_returns_200(self):
        ctx, transport, events = _udp_ctx()
        handler = SIPHandler(_cfg("sip", transport="udp"))
        req = (b"OPTIONS sip:honey SIP/2.0\r\n"
               b"Via: SIP/2.0/UDP 1.2.3.4\r\n"
               b"From: <sip:scan@example>\r\n"
               b"To: <sip:honey@target>\r\n"
               b"Call-ID: abc\r\n"
               b"CSeq: 1 OPTIONS\r\n"
               b"User-Agent: sipvicious 0.3.2\r\n"
               b"Content-Length: 0\r\n\r\n")
        _run(handler.on_datagram(req, ctx))
        assert len(transport.sent) == 1
        reply = transport.sent[0][0]
        assert b"SIP/2.0 200 OK" in reply
        assert b"Allow: INVITE" in reply
        assert any(e[0] == "sip_request" and e[1]["method"] == "OPTIONS"
                   for e in events)
        # user_agent captured
        assert any("sipvicious" in (e[1].get("user_agent") or "")
                   for e in events)

    def test_register_challenges_with_401_nonce(self):
        ctx, transport, _ = _udp_ctx()
        handler = SIPHandler(_cfg("sip", transport="udp"))
        req = (b"REGISTER sip:target SIP/2.0\r\n"
               b"Via: SIP/2.0/UDP 1.2.3.4\r\n"
               b"From: <sip:a@b>\r\n"
               b"To: <sip:a@b>\r\n"
               b"Call-ID: c1\r\n"
               b"CSeq: 1 REGISTER\r\n\r\n")
        _run(handler.on_datagram(req, ctx))
        reply = transport.sent[0][0]
        assert b"SIP/2.0 401 Unauthorized" in reply
        assert b"WWW-Authenticate" in reply
        assert b"nonce=" in reply

    def test_non_sip_ignored(self):
        ctx, transport, _ = _udp_ctx()
        handler = SIPHandler(_cfg("sip", transport="udp"))
        _run(handler.on_datagram(b"GARBAGE\r\n\r\n", ctx))
        assert transport.sent == []


# ---------- IPMI ----------
class TestIPMI:
    def test_presence_ping_gets_pong(self):
        ctx, transport, events = _udp_ctx()
        handler = IPMIHandler(_cfg("ipmi", transport="udp"))
        ping = (b"\x06\x00\xff\x06"
                b"\x00\x00\x11\xbe"
                b"\x80\x42\x00\x00")
        _run(handler.on_datagram(ping, ctx))
        assert len(transport.sent) == 1
        pong = transport.sent[0][0]
        assert pong[:4] == b"\x06\x00\xff\x06"
        assert pong[8] == 0x40       # Presence Pong
        assert pong[9] == 0x42       # tag echoed
        assert pong[11] == 0x10      # data length
        assert any(e[0] == "ipmi_ping" for e in events)

    def test_short_datagram_ignored(self):
        ctx, transport, _ = _udp_ctx()
        handler = IPMIHandler(_cfg("ipmi", transport="udp"))
        _run(handler.on_datagram(b"\x06\x00\xff", ctx))
        assert transport.sent == []


# ---------- CoAP ----------
class TestCoAP:
    def test_confirmable_get_gets_205(self):
        ctx, transport, events = _udp_ctx()
        handler = CoAPHandler(_cfg("coap", transport="udp"))
        # Version=1, Type=CON(0), TKL=2, Code=1 (GET), MsgID=0xbeef
        # Then token (2 bytes), then Uri-Path options for ".well-known"/"core"
        header = bytes([0x42, 0x01, 0xbe, 0xef]) + b"\x11\x22"
        # Uri-Path option: delta=11 (requires extended), length
        # Use delta=11 → nibble=11 (since 13>11). Actually 11 fits in 4 bits? 11 = 0xB OK.
        path1 = b".well-known"
        path2 = b"core"
        opt1 = bytes([(11 << 4) | len(path1)]) + path1
        # Next option same type (delta=0 from prev)
        opt2 = bytes([(0 << 4) | len(path2)]) + path2
        payload = header + opt1 + opt2
        _run(handler.on_datagram(payload, ctx))

        assert len(transport.sent) == 1
        reply = transport.sent[0][0]
        assert reply[1] == 0x45          # 2.05 Content
        assert reply[2:4] == b"\xbe\xef"  # echoed msg id
        # coap_request event captured path and method
        assert events
        evt = events[0][1]
        assert evt["method"] == "GET"
        assert evt["path"] == ".well-known/core"

    def test_non_confirmable_silent(self):
        ctx, transport, _ = _udp_ctx()
        handler = CoAPHandler(_cfg("coap", transport="udp"))
        # Type=1 (NON), GET, no options, no path
        header = bytes([0x50, 0x01, 0x00, 0x01])
        _run(handler.on_datagram(header, ctx))
        assert transport.sent == []


# ---------- Modbus ----------
class TestModbus:
    @staticmethod
    def _mbap(trans, unit, pdu):
        return struct.pack(">HHHB", trans, 0, 1 + len(pdu), unit) + pdu

    def test_read_holding_registers_reply(self):
        ctx, writer, events = _tcp_ctx()
        handler = ModbusHandler(_cfg("modbus"))
        # FC=3, start=0x0000, quantity=4
        pdu = bytes([3]) + struct.pack(">HH", 0, 4)
        _run(handler.on_data(self._mbap(0x42, 1, pdu), ctx))
        # Reply framing
        reply = bytes(writer.buffer)
        assert reply[:2] == b"\x00\x42"  # transaction id echoed
        assert reply[7] == 3              # function code
        assert reply[8] == 8              # byte count = 4 registers * 2
        assert any(e[0] == "modbus_request" and e[1]["function"] == 3
                   for e in events)

    def test_unknown_function_returns_exception(self):
        ctx, writer, _ = _tcp_ctx()
        handler = ModbusHandler(_cfg("modbus"))
        pdu = bytes([99]) + b"\x00\x00"
        _run(handler.on_data(self._mbap(1, 1, pdu), ctx))
        reply = bytes(writer.buffer)
        assert reply[7] == (99 | 0x80)    # exception flag set
        assert reply[8] == 1               # illegal function

    def test_fragmented_frame(self):
        ctx, writer, _ = _tcp_ctx()
        handler = ModbusHandler(_cfg("modbus"))
        full = self._mbap(7, 1, bytes([1]) + struct.pack(">HH", 0, 8))
        _run(handler.on_data(full[:4], ctx))
        assert len(writer.buffer) == 0
        _run(handler.on_data(full[4:], ctx))
        assert len(writer.buffer) > 0


# ---------- MQTT ----------
class TestMQTT:
    @staticmethod
    def _encode_varint(n):
        out = bytearray()
        while True:
            byte = n & 0x7F
            n >>= 7
            if n:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
        return bytes(out)

    @staticmethod
    def _utf8(s):
        b = s.encode()
        return len(b).to_bytes(2, "big") + b

    def test_connect_with_user_pass_captured(self):
        ctx, writer, events = _tcp_ctx()
        handler = MQTTHandler(_cfg("mqtt"))
        # CONNECT payload: protocol name "MQTT" v4
        proto = self._utf8("MQTT")
        level = bytes([4])
        flags = bytes([0xC2])  # UserName | Password | CleanSession
        keep = b"\x00\x3c"
        payload = self._utf8("clientX") + self._utf8("root") + self._utf8("toor")
        body = proto + level + flags + keep + payload
        packet = bytes([1 << 4]) + self._encode_varint(len(body)) + body
        _run(handler.on_data(packet, ctx))

        # CONNACK sent
        assert bytes(writer.buffer[:4]) == bytes([0x20, 0x02, 0x00, 0x00])
        # credentials event captured
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "root"
        assert creds[0][1]["password"] == "toor"
        assert creds[0][1]["client_id"] == "clientX"

    def test_pingreq_gets_pingresp(self):
        ctx, writer, _ = _tcp_ctx()
        handler = MQTTHandler(_cfg("mqtt"))
        _run(handler.on_data(bytes([0xC0, 0x00]), ctx))
        assert bytes(writer.buffer) == bytes([0xD0, 0x00])


# ---------- MySQL ----------
class TestMySQL:
    def test_greeting_sent_on_connect(self):
        ctx, writer, _ = _tcp_ctx()
        handler = MySQLHandler(_cfg("mysql"))
        _run(handler.on_connect(ctx))
        # First 3 bytes = LE length, then seq=0
        length = int.from_bytes(writer.buffer[:3], "little")
        assert writer.buffer[3] == 0x00
        assert writer.buffer[4] == 10  # protocol version
        # MySQL version string present
        assert b"5.7" in bytes(writer.buffer[:length + 4])

    def test_login_packet_captured(self):
        ctx, writer, events = _tcp_ctx()
        handler = MySQLHandler(_cfg("mysql"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()

        # Build a minimal v4.1 login packet
        caps = 0x00008200  # PROTOCOL_41 | SECURE_CONNECTION
        max_packet = 16 * 1024 * 1024
        charset = 0x21
        body = (struct.pack("<I", caps)
                + struct.pack("<I", max_packet)
                + bytes([charset])
                + b"\x00" * 23
                + b"attacker\x00"           # username
                + bytes([4]) + b"\xaa" * 4)  # auth len + auth bytes
        header = struct.pack("<I", len(body))[:3] + bytes([1])
        _run(handler.on_data(header + body, ctx))

        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "attacker"
        # Access denied error packet returned
        assert b"Access denied" in bytes(writer.buffer)
        assert ctx.closed


# ---------- Postgres ----------
class TestPostgres:
    def test_sslrequest_then_startup(self):
        ctx, writer, events = _tcp_ctx()
        handler = PostgresHandler(_cfg("postgres"))

        ssl_req = struct.pack(">II", 8, 0x04D2162F)
        _run(handler.on_data(ssl_req, ctx))
        assert bytes(writer.buffer) == b"N"
        writer.buffer.clear()

        startup_body = (b"user\x00scanner\x00"
                        b"database\x00target\x00"
                        b"\x00")
        startup = struct.pack(">II", 8 + len(startup_body), 0x00030000) + startup_body
        _run(handler.on_data(startup, ctx))
        # AuthenticationCleartextPassword
        assert bytes(writer.buffer[:9]) == b"R" + struct.pack(">II", 8, 3)
        writer.buffer.clear()

        # Client sends PasswordMessage
        password = b"s3cr3t\x00"
        pmsg = b"p" + struct.pack(">I", 4 + len(password)) + password
        _run(handler.on_data(pmsg, ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds
        assert creds[0][1]["username"] == "scanner"
        assert creds[0][1]["password"] == "s3cr3t"
        assert creds[0][1]["database"] == "target"
        # ErrorResponse returned and connection closed
        assert writer.buffer.startswith(b"E")
        assert ctx.closed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
