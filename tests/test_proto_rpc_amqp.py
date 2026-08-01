"""Tests for the rpcbind (UDP/111) and AMQP (TCP/5672) protocol handlers."""

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols.amqp import AMQPHandler
from honeyknot.protocols.base import ConnectionContext, DatagramContext
from honeyknot.protocols.rpcbind import RPCBindHandler


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


def _cfg(protocol, transport="tcp", **opts):
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         transport=transport, protocol_opts=opts)


def _run(coro):
    return asyncio.run(coro)


# ---------- rpcbind ----------

def _rpc_call(xid=0x1234, prog=100000, vers=2, proc=0, args=b"",
              msg_type=0, rpcvers=2):
    """ONC RPC call with null credential + null verifier."""
    return (struct.pack(">6I", xid, msg_type, rpcvers, prog, vers, proc)
            + struct.pack(">II", 0, 0)      # cred: AUTH_NONE, len 0
            + struct.pack(">II", 0, 0)      # verf: AUTH_NONE, len 0
            + args)


class TestRPCBind:
    def test_null_gets_bounded_success_reply(self):
        ctx, transport, events = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        req = _rpc_call(xid=0xAABBCCDD, proc=0)
        _run(handler.on_datagram(req, ctx))
        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        # Non-amplification invariant.
        assert len(reply) <= len(req)
        # xid echoed, msg_type=REPLY, accept_stat=SUCCESS, no results.
        xid, msg_type, reply_stat, vf, vl, stat = struct.unpack(">6I", reply[:24])
        assert xid == 0xAABBCCDD
        assert msg_type == 1
        assert reply_stat == 0
        assert (vf, vl) == (0, 0)
        assert stat == 0
        assert any(e[0] == "rpc_call" and e[1]["procedure_name"] == "NULL"
                   for e in events)

    def test_getport_nfs_replies_port_zero(self):
        ctx, transport, events = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        args = struct.pack(">4I", 100003, 3, 17, 0)  # nfs v3 over udp
        req = _rpc_call(proc=3, args=args)
        _run(handler.on_datagram(req, ctx))
        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        assert len(reply) <= len(req)
        # Result is a single u4 port at the tail: 0 = not registered.
        assert struct.unpack(">I", reply[-4:])[0] == 0
        getports = [e for e in events if e[0] == "rpc_getport"]
        assert getports
        assert getports[0][1]["query_program"] == 100003
        assert getports[0][1]["query_program_name"] == "nfs"
        assert getports[0][1]["query_version"] == 3
        assert getports[0][1]["query_protocol"] == "udp"

    def test_getport_configurable_port(self):
        ctx, transport, _ = _udp_ctx()
        handler = RPCBindHandler(
            _cfg("rpcbind", transport="udp", getport_port=2049))
        req = _rpc_call(proc=3, args=struct.pack(">4I", 100003, 3, 6, 0))
        _run(handler.on_datagram(req, ctx))
        reply, _ = transport.sent[0]
        assert len(reply) <= len(req)
        assert struct.unpack(">I", reply[-4:])[0] == 2049

    def test_dump_refused_never_populated(self):
        ctx, transport, events = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        req = _rpc_call(proc=4)
        _run(handler.on_datagram(req, ctx))
        assert any(e[0] == "rpc_dump_refused" for e in events)
        # At most an empty-list reply, never larger than the request, and the
        # value_follows discriminator at the tail must be 0 (no map entries).
        for reply, _addr in transport.sent:
            assert len(reply) <= len(req)
            assert len(reply) == 28  # accepted-reply header + value_follows
            assert struct.unpack(">I", reply[-4:])[0] == 0

    def test_callit_gets_no_reply(self):
        ctx, transport, events = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        inner = struct.pack(">3I", 100003, 3, 1) + b"\x00" * 8
        _run(handler.on_datagram(_rpc_call(proc=5, args=inner), ctx))
        assert transport.sent == []  # CALLIT is a proxy/amplifier: silence
        callits = [e for e in events if e[0] == "rpc_callit"]
        assert callits
        assert callits[0][1]["program"] == 100003
        assert callits[0][1]["version"] == 3
        assert callits[0][1]["procedure"] == 1

    def test_truncated_datagram_no_reply_no_raise(self):
        ctx, transport, _ = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        _run(handler.on_datagram(b"\x00\x01\x02\x03\x04\x05\x06\x07", ctx))
        assert transport.sent == []

    def test_non_call_message_dropped(self):
        ctx, transport, _ = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        _run(handler.on_datagram(_rpc_call(msg_type=1), ctx))
        assert transport.sent == []

    def test_unknown_procedure_bounded_proc_unavail(self):
        ctx, transport, _ = _udp_ctx()
        handler = RPCBindHandler(_cfg("rpcbind", transport="udp"))
        req = _rpc_call(proc=1)  # SET
        _run(handler.on_datagram(req, ctx))
        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        assert len(reply) <= len(req)
        assert struct.unpack(">I", reply[20:24])[0] == 2  # PROC_UNAVAIL


# ---------- AMQP ----------

AMQP_HEADER = b"AMQP\x00\x00\x09\x01"


def _frame(ftype, channel, payload):
    return struct.pack(">BHI", ftype, channel, len(payload)) + payload + b"\xce"


def _method(channel, class_id, method_id, args):
    return _frame(1, channel, struct.pack(">HH", class_id, method_id) + args)


def _shortstr(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


def _longstr(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _table(entries: dict) -> bytes:
    body = b""
    for k, v in entries.items():
        kb, vb = k.encode(), v.encode()
        body += bytes([len(kb)]) + kb + b"S" + _longstr(vb)
    return struct.pack(">I", len(body)) + body


def _start_ok(mechanism: str, response: bytes, props: dict | None = None) -> bytes:
    args = (_table(props or {"product": "pika", "version": "1.2.0",
                             "platform": "CPython"})
            + _shortstr(mechanism) + _longstr(response) + _shortstr("en_US"))
    return _method(0, 10, 11, args)


def _parse_frames(buf: bytes):
    """Split a byte stream into (type, channel, payload) frames, checking
    the declared size and the 0xCE end marker for every frame."""
    frames = []
    pos = 0
    while pos < len(buf):
        assert pos + 8 <= len(buf), "truncated frame header"
        ftype, chan, size = struct.unpack(">BHI", buf[pos:pos + 7])
        end = pos + 7 + size
        assert end < len(buf), "declared size overruns the buffer"
        assert buf[end] == 0xCE, "missing frame-end marker"
        frames.append((ftype, chan, bytes(buf[pos + 7:end])))
        pos = end + 1
    return frames


class TestAMQP:
    def _connect(self, **opts):
        ctx, writer, events = _tcp_ctx()
        handler = AMQPHandler(_cfg("amqp", **opts))
        _run(handler.on_connect(ctx))
        return handler, ctx, writer, events

    def test_header_gets_connection_start(self):
        handler, ctx, writer, _ = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        frames = _parse_frames(bytes(writer.buffer))
        assert len(frames) == 1
        ftype, chan, payload = frames[0]
        assert ftype == 1 and chan == 0
        # Connection.Start = class 10, method 10; frame ends in 0xCE and its
        # declared size matches the payload (both checked by _parse_frames).
        assert struct.unpack(">HH", payload[:4]) == (10, 10)
        assert payload[4:6] == b"\x00\x09"  # version 0-9
        assert b"PLAIN AMQPLAIN" in payload
        assert b"RabbitMQ" in payload

    def test_plain_credentials_then_tune(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        writer.buffer.clear()
        _run(handler.on_data(_start_ok("PLAIN", b"\x00guest\x00guest"), ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds
        assert creds[0][1]["service"] == "amqp"
        assert creds[0][1]["username"] == "guest"
        assert creds[0][1]["password"] == "guest"
        assert creds[0][1]["mechanism"] == "PLAIN"
        clients = [e for e in events if e[0] == "amqp_client"]
        assert clients and clients[0][1]["product"] == "pika"
        # Reply is Connection.Tune (10/30).
        frames = _parse_frames(bytes(writer.buffer))
        assert any(struct.unpack(">HH", p[:4]) == (10, 30)
                   for _t, _c, p in frames)

    def test_amqplain_credentials(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        writer.buffer.clear()
        # Bare table body (no leading u4 size), the spec-blessed form.
        body = (b"\x05LOGIN" + b"S" + _longstr(b"admin")
                + b"\x08PASSWORD" + b"S" + _longstr(b"s3cret"))
        _run(handler.on_data(_start_ok("AMQPLAIN", body), ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds
        assert creds[0][1]["username"] == "admin"
        assert creds[0][1]["password"] == "s3cret"
        assert creds[0][1]["mechanism"] == "AMQPLAIN"

    def test_amqplain_with_size_prefix(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        body = (b"\x05LOGIN" + b"S" + _longstr(b"root")
                + b"\x08PASSWORD" + b"S" + _longstr(b"toor"))
        _run(handler.on_data(
            _start_ok("AMQPLAIN", struct.pack(">I", len(body)) + body), ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "root"
        assert creds[0][1]["password"] == "toor"

    def test_open_vhost_gets_openok(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        writer.buffer.clear()
        open_args = _shortstr("/") + _shortstr("") + b"\x00"
        _run(handler.on_data(_method(0, 10, 40, open_args), ctx))
        opens = [e for e in events if e[0] == "amqp_open"]
        assert opens and opens[0][1]["vhost"] == "/"
        frames = _parse_frames(bytes(writer.buffer))
        assert any(struct.unpack(">HH", p[:4]) == (10, 41)
                   for _t, _c, p in frames)

    def test_channel_open_and_heartbeat(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        writer.buffer.clear()
        _run(handler.on_data(_method(1, 20, 10, _shortstr("")), ctx))
        assert any(e[0] == "amqp_channel_open" and e[1]["channel"] == 1
                   for e in events)
        frames = _parse_frames(bytes(writer.buffer))
        assert frames[0][1] == 1  # OpenOk on the same channel
        assert struct.unpack(">HH", frames[0][2][:4]) == (20, 11)
        writer.buffer.clear()
        _run(handler.on_data(_frame(8, 0, b""), ctx))
        assert bytes(writer.buffer) == _frame(8, 0, b"")  # heartbeat echoed

    def test_frame_split_across_reads(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        full = _start_ok("PLAIN", b"\x00u\x00p")
        _run(handler.on_data(full[:10], ctx))
        assert not [e for e in events if e[0] == "credentials"]
        _run(handler.on_data(full[10:], ctx))
        creds = [e for e in events if e[0] == "credentials"]
        assert creds and creds[0][1]["username"] == "u"
        assert creds[0][1]["password"] == "p"

    def test_bad_frame_end_closes(self):
        handler, ctx, writer, _ = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        bad = bytearray(_method(0, 10, 31, b""))
        bad[-1] = 0xAB
        _run(handler.on_data(bytes(bad), ctx))
        assert ctx.closed

    def test_three_bytes_then_silence_no_raise(self):
        handler, ctx, writer, _ = self._connect()
        _run(handler.on_data(b"AMQ", ctx))
        assert bytes(writer.buffer) == b""
        assert not ctx.closed

    def test_wrong_protocol_header_echoes_ours_and_closes(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(b"AMQP\x00\x01\x00\x00", ctx))  # AMQP 1.0
        assert bytes(writer.buffer) == AMQP_HEADER
        assert ctx.closed
        bad = [e for e in events if e[0] == "amqp_bad_protocol_header"]
        assert bad and bad[0][1]["header_hex"] == b"AMQP\x00\x01\x00\x00".hex()

    def test_unknown_method_logged(self):
        handler, ctx, writer, events = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        # Queue.Declare (50/10) on channel 1
        args = struct.pack(">H", 0) + _shortstr("exfil") + b"\x00" + _table({})
        _run(handler.on_data(_method(1, 50, 10, args), ctx))
        methods = [e for e in events if e[0] == "amqp_method"]
        assert methods
        assert methods[0][1]["method"] == "Queue.Declare"
        assert methods[0][1]["channel"] == 1

    def test_oversize_frame_closes(self):
        handler, ctx, writer, _ = self._connect()
        _run(handler.on_data(AMQP_HEADER, ctx))
        header = struct.pack(">BHI", 1, 0, (1 << 20) + 1)
        _run(handler.on_data(header, ctx))
        assert ctx.closed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
