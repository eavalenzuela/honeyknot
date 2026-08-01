"""Tests for the ZooKeeper, rsync, and finger protocol handlers."""

from __future__ import annotations

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols.base import ConnectionContext
from honeyknot.protocols.finger import FingerHandler
from honeyknot.protocols.rsync import RsyncHandler
from honeyknot.protocols.zookeeper import ZooKeeperHandler


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


def _tcp_ctx(port=0):
    w = _FakeWriter()
    events: list = []
    ctx = ConnectionContext(
        writer=w, addr=("203.0.113.9", 54321), port=port,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, w, events


def _run(coro):
    return asyncio.run(coro)


def _zk(opts=None):
    return ZooKeeperHandler(ServiceConfig(
        port=2181, service_type="tcp", protocol="zookeeper",
        protocol_opts=opts or {},
    ))


def _rsync(opts=None):
    return RsyncHandler(ServiceConfig(
        port=873, service_type="tcp", protocol="rsync",
        protocol_opts=opts or {},
    ))


def _finger(opts=None):
    return FingerHandler(ServiceConfig(
        port=79, service_type="tcp", protocol="finger",
        protocol_opts=opts or {},
    ))


# ---------- ZooKeeper ----------
class TestZooKeeper:
    def _session(self, handler, chunks):
        ctx, w, events = _tcp_ctx(2181)

        async def go():
            await handler.on_connect(ctx)
            for chunk in chunks:
                if ctx.closed:
                    break
                await handler.on_data(chunk, ctx)

        _run(go())
        return ctx, w, events

    def test_ruok_returns_exactly_imok(self):
        ctx, w, events = self._session(_zk(), [b"ruok"])
        assert bytes(w.buffer) == b"imok"
        cmds = [e for e in events if e[0] == "zookeeper_command"]
        assert cmds == [("zookeeper_command", {"command": "ruok", "known": True})]
        assert ctx.closed

    def test_ruok_with_trailing_newline(self):
        _, w, _ = self._session(_zk(), [b"ruok\n"])
        assert bytes(w.buffer) == b"imok"

    def test_mntr_contains_zk_keys(self):
        _, w, _ = self._session(_zk(), [b"mntr\n"])
        text = bytes(w.buffer).decode()
        assert "zk_version\t" in text
        assert "zk_avg_latency\t0" in text
        assert "zk_num_alive_connections\t" in text
        assert "zk_znode_count\t27" in text

    def test_stat_lists_peer_and_mode(self):
        _, w, _ = self._session(_zk({"mode": "leader", "node_count": 99}), [b"stat"])
        text = bytes(w.buffer).decode()
        assert text.startswith("Zookeeper version: ")
        assert "/203.0.113.9:54321" in text
        assert "Mode: leader" in text
        assert "Node count: 99" in text

    def test_unknown_four_letter_word(self):
        ctx, w, events = self._session(_zk(), [b"abcd\n"])
        assert bytes(w.buffer) == (
            b"abcd is not executed because it is not in the whitelist.\n")
        cmds = [e for e in events if e[0] == "zookeeper_command"]
        assert cmds == [("zookeeper_command", {"command": "abcd", "known": False})]
        assert ctx.closed

    @staticmethod
    def _connect_frame(timeout=30000, session_id=0):
        body = (struct.pack(">iqiq", 0, 0, timeout, session_id)
                + struct.pack(">i", 16) + b"\x00" * 16 + b"\x00")
        return struct.pack(">I", len(body)) + body

    def test_binary_connect_request(self):
        ctx, w, events = self._session(_zk(), [self._connect_frame(timeout=4000)])
        conns = [e for e in events if e[0] == "zookeeper_connect"]
        assert len(conns) == 1
        fields = conns[0][1]
        assert fields["timeout_ms"] == 4000
        assert fields["protocol_version"] == 0
        assert fields["session_id"] == 0
        # Well-formed length-prefixed ConnectResponse.
        resp = bytes(w.buffer)
        assert len(resp) >= 4
        declared = int.from_bytes(resp[:4], "big")
        assert declared == len(resp) - 4 == 36
        assert int.from_bytes(resp[8:12], "big") == 4000  # granted timeout
        assert int.from_bytes(resp[12:20], "big") != 0    # non-zero session id
        assert not ctx.closed  # connection stays open for more frames

    def test_ping_after_connect_gets_reply(self):
        ping_body = struct.pack(">ii", -2, 11)
        ping = struct.pack(">I", len(ping_body)) + ping_body
        ctx, w, events = self._session(_zk(), [self._connect_frame(), ping])
        reqs = [e for e in events if e[0] == "zookeeper_request"]
        assert len(reqs) == 1
        assert reqs[0][1]["opcode"] == 11
        assert reqs[0][1]["opcode_name"] == "ping"
        assert reqs[0][1]["xid"] == -2
        # The ping reply is a 16-byte ReplyHeader after the 40-byte connect
        # response.
        reply = bytes(w.buffer)[40:]
        assert int.from_bytes(reply[:4], "big") == 16
        assert len(reply) == 20

    def test_truncated_binary_frame_does_not_raise(self):
        ctx, w, _ = self._session(_zk(), [struct.pack(">I", 500) + b"\x00" * 10])
        assert bytes(w.buffer) == b""
        assert not ctx.closed

    def test_two_bytes_then_silence(self):
        ctx, w, _ = self._session(_zk(), [b"ru"])
        assert bytes(w.buffer) == b""
        assert not ctx.closed

    def test_oversized_frame_closes(self):
        ctx, _, _ = self._session(_zk(), [struct.pack(">I", 2 * 1024 * 1024)])
        assert ctx.closed


# ---------- rsync ----------
class TestRsync:
    def _session(self, handler, chunks):
        ctx, w, events = _tcp_ctx(873)

        async def go():
            await handler.on_connect(ctx)
            for chunk in chunks:
                if ctx.closed:
                    break
                await handler.on_data(chunk, ctx)

        _run(go())
        return ctx, w, events

    def test_greeting_on_connect(self):
        _, w, _ = self._session(_rsync(), [])
        assert bytes(w.buffer) == b"@RSYNCD: 31.0\n"

    def test_list_modules(self):
        ctx, w, events = self._session(_rsync(), [b"@RSYNCD: 31.0\n#list\n"])
        text = bytes(w.buffer).decode()
        assert "backup\tNightly server backups\n" in text
        assert "www\t" in text
        assert text.endswith("@RSYNCD: EXIT\n")
        assert ctx.closed
        assert any(e[0] == "rsync_list" for e in events)

    def test_known_module_auth_and_credentials(self):
        handler = _rsync()
        ctx, w, events = _tcp_ctx(873)

        async def go():
            await handler.on_connect(ctx)
            await handler.on_data(b"@RSYNCD: 31.0\nbackup\n", ctx)
            await handler.on_data(b"alice czNjcmV0aGFzaA\n", ctx)

        _run(go())
        text = bytes(w.buffer).decode()
        assert "@RSYNCD: AUTHREQD " in text
        challenge = text.split("@RSYNCD: AUTHREQD ", 1)[1].split("\n", 1)[0]
        assert "@RSYNCD: OK\n" in text

        mods = [e for e in events if e[0] == "rsync_module"]
        assert mods == [("rsync_module", {"module": "backup", "known": True})]
        creds = [e for e in events if e[0] == "credentials"]
        assert len(creds) == 1
        fields = creds[0][1]
        assert fields["service"] == "rsync"
        assert fields["username"] == "alice"
        assert fields["password"] is None
        assert fields["auth"] == "challenge"
        assert fields["challenge"] == challenge
        assert fields["response"] == "czNjcmV0aGFzaA"

    def test_unknown_module(self):
        ctx, w, events = self._session(_rsync(), [b"@RSYNCD: 31.0\nsecrets\n"])
        assert b"@ERROR: Unknown module 'secrets'\n" in bytes(w.buffer)
        assert ctx.closed
        mods = [e for e in events if e[0] == "rsync_module"]
        assert mods == [("rsync_module", {"module": "secrets", "known": False})]

    def test_args_collected_after_auth_off(self):
        handler = _rsync({"auth": False})
        ctx, w, events = _tcp_ctx(873)

        async def go():
            await handler.on_connect(ctx)
            await handler.on_data(b"@RSYNCD: 31.0\nwww\n", ctx)
            before = len(w.buffer)
            await handler.on_data(b"--server\0--sender\0.\0www/\0\0", ctx)
            return before

        before = _run(go())
        args_events = [e for e in events if e[0] == "rsync_args"]
        assert len(args_events) == 1
        fields = args_events[0][1]
        assert fields["module"] == "www"
        assert fields["args"] == ["--server", "--sender", ".", "www/"]
        # 4-byte checksum seed sent after the terminator.
        assert len(w.buffer) - before == 4

    def test_custom_module_list_from_opts(self):
        handler = _rsync({"modules": [{"name": "vmimages", "comment": "ESXi exports"}]})
        _, w, _ = self._session(handler, [b"@RSYNCD: 31.0\n#list\n"])
        text = bytes(w.buffer).decode()
        assert "vmimages\tESXi exports\n" in text
        assert "backup\t" not in text

    def test_binary_garbage_gets_error_not_traceback(self):
        ctx, w, _ = self._session(_rsync(), [b"\xde\xad\xbe\xef\x01\x02\n"])
        assert b"@ERROR" in bytes(w.buffer)
        assert ctx.closed

    def test_long_garbage_without_newline(self):
        ctx, w, _ = self._session(_rsync(), [b"\x00\xff\x13\x37" * 300])
        assert b"@ERROR" in bytes(w.buffer)
        assert ctx.closed


# ---------- finger ----------
class TestFinger:
    def _session(self, handler, chunks):
        ctx, w, events = _tcp_ctx(79)

        async def go():
            await handler.on_connect(ctx)
            for chunk in chunks:
                if ctx.closed:
                    break
                await handler.on_data(chunk, ctx)

        _run(go())
        return ctx, w, events

    def test_empty_query_lists_users(self):
        ctx, w, events = self._session(_finger(), [b"\r\n"])
        text = bytes(w.buffer).decode()
        assert "Login" in text and "Tty" in text
        assert "root" in text
        assert "admin" in text
        assert ctx.closed
        queries = [e for e in events if e[0] == "finger_query"]
        assert queries == [("finger_query", {"query": "", "verbose": False, "user": ""})]

    def test_known_user_block(self):
        ctx, w, _ = self._session(_finger(), [b"root\r\n"])
        text = bytes(w.buffer).decode()
        assert "Login: root" in text
        assert "Directory: /root" in text
        assert "Shell: /bin/bash" in text
        assert ctx.closed

    def test_unknown_user(self):
        _, w, events = self._session(_finger(), [b"nosuchuser\r\n"])
        assert b"finger: nosuchuser: no such user.\r\n" in bytes(w.buffer)
        queries = [e for e in events if e[0] == "finger_query"]
        assert queries[0][1]["user"] == "nosuchuser"

    def test_relay_refused(self):
        ctx, w, events = self._session(_finger(), [b"root@1.2.3.4\r\n"])
        assert b"Finger forwarding service denied\r\n" in bytes(w.buffer)
        relays = [e for e in events if e[0] == "finger_relay"]
        assert len(relays) == 1
        assert relays[0][1]["target_host"] == "1.2.3.4"
        assert relays[0][1]["query"] == "root@1.2.3.4"
        # No user block, no forwarding.
        assert b"Login:" not in bytes(w.buffer)
        assert ctx.closed

    def test_verbose_query_flag(self):
        _, w, events = self._session(_finger(), [b"/W root\r\n"])
        queries = [e for e in events if e[0] == "finger_query"]
        assert queries[0][1]["verbose"] is True
        assert queries[0][1]["user"] == "root"
        assert b"Login: root" in bytes(w.buffer)

    def test_control_characters_sanitized(self):
        _, w, events = self._session(_finger(), [b"ro\x1b[31mot\x07\r\n"])
        reply = bytes(w.buffer)
        assert b"\x1b" not in reply
        assert b"\x07" not in reply
        assert b"no such user." in reply
        queries = [e for e in events if e[0] == "finger_query"]
        assert "\x1b" not in queries[0][1]["query"]

    def test_split_query_across_chunks(self):
        _, w, _ = self._session(_finger(), [b"ro", b"ot\r\n"])
        assert b"Login: root" in bytes(w.buffer)

    def test_oversized_query_closed(self):
        ctx, w, _ = self._session(_finger(), [b"A" * 2048])
        assert b"query too long" in bytes(w.buffer)
        assert ctx.closed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
