"""Tests for the RTSP (TCP/554) and SOCKS4/4a/5 (TCP/1080) handlers."""

from __future__ import annotations

import asyncio
import base64
import logging

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols.base import ConnectionContext
from honeyknot.protocols.rtsp import RTSPHandler
from honeyknot.protocols.socks import SocksHandler


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


def _tcp_ctx():
    w = _FakeWriter()
    events: list = []
    ctx = ConnectionContext(
        writer=w, addr=("198.51.100.7", 51515), port=0,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, w, events


def _run(coro):
    return asyncio.run(coro)


def _events(events, name):
    return [f for n, f in events if n == name]


# ---------- RTSP ----------

def _rtsp_handler(**opts):
    return RTSPHandler(ServiceConfig(
        port=554, service_type="tcp", protocol="rtsp", protocol_opts=opts,
    ))


def _rtsp_session(handler):
    ctx, writer, events = _tcp_ctx()
    _run(handler.on_connect(ctx))
    return ctx, writer, events


def _req(method: str, url: str = "rtsp://cam/live.sdp", cseq: int = 1,
         extra: str = "") -> bytes:
    return (f"{method} {url} RTSP/1.0\r\nCSeq: {cseq}\r\n"
            f"User-Agent: LibVLC/3.0\r\n{extra}\r\n").encode()


class TestRTSP:
    def test_options_echoes_cseq_and_lists_public(self):
        handler = _rtsp_handler()
        ctx, writer, events = _rtsp_session(handler)
        _run(handler.on_data(_req("OPTIONS", cseq=3), ctx))

        reply = bytes(writer.buffer)
        assert reply.startswith(b"RTSP/1.0 200 OK\r\n")
        assert b"CSeq: 3\r\n" in reply
        assert b"Public: OPTIONS, DESCRIBE, SETUP, PLAY" in reply
        assert b"Server: Rtsp Server/2.0" in reply

        request_events = _events(events, "rtsp_request")
        assert request_events[0]["method"] == "OPTIONS"
        assert request_events[0]["url"] == "rtsp://cam/live.sdp"
        assert request_events[0]["cseq"] == "3"
        assert request_events[0]["user_agent"] == "LibVLC/3.0"

    def test_describe_unauthenticated_offers_digest_and_basic(self):
        handler = _rtsp_handler(realm="Test Cam")
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(_req("DESCRIBE", cseq=2), ctx))

        reply = bytes(writer.buffer)
        assert reply.startswith(b"RTSP/1.0 401 Unauthorized\r\n")
        assert b'WWW-Authenticate: Digest realm="Test Cam", nonce="' in reply
        assert b'WWW-Authenticate: Basic realm="Test Cam"' in reply
        assert b"CSeq: 2" in reply

    def test_nonce_is_stable_within_a_session(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(_req("DESCRIBE", cseq=1), ctx))
        _run(handler.on_data(_req("DESCRIBE", cseq=2), ctx))
        nonces = bytes(writer.buffer).split(b'nonce="')
        assert len(nonces) == 3
        assert nonces[1][:32] == nonces[2][:32]
        assert nonces[1][:32] == ctx.state["nonce"].encode()

    def test_describe_basic_captures_creds_and_returns_sdp(self):
        handler = _rtsp_handler()
        ctx, writer, events = _rtsp_session(handler)
        blob = base64.b64encode(b"admin:xc3511").decode()
        _run(handler.on_data(
            _req("DESCRIBE", cseq=2, extra=f"Authorization: Basic {blob}\r\n"),
            ctx))

        creds = _events(events, "credentials")
        assert len(creds) == 1
        assert creds[0]["service"] == "rtsp"
        assert creds[0]["username"] == "admin"
        assert creds[0]["password"] == "xc3511"

        reply = bytes(writer.buffer)
        assert reply.startswith(b"RTSP/1.0 200 OK\r\n")
        assert b"Content-Type: application/sdp" in reply
        assert b"Content-Base: rtsp://cam/live.sdp/" in reply
        assert b"m=video 0 RTP/AVP 96" in reply
        assert b"a=rtpmap:96 H264/90000" in reply
        assert b"a=control:trackID=0" in reply

    def test_basic_with_garbage_blob_does_not_raise(self):
        handler = _rtsp_handler()
        ctx, writer, events = _rtsp_session(handler)
        _run(handler.on_data(
            _req("DESCRIBE", extra="Authorization: Basic !!!not-base64\r\n"),
            ctx))
        assert _events(events, "credentials")
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 200 OK")

    def test_describe_digest_records_hash(self):
        handler = _rtsp_handler()
        ctx, writer, events = _rtsp_session(handler)
        auth = ('Digest username="root", realm="IP Camera", '
                'nonce="deadbeef", uri="rtsp://cam/live.sdp", '
                'response="8f3a1c2d4e5f60718293a4b5c6d7e8f9"')
        _run(handler.on_data(
            _req("DESCRIBE", cseq=4, extra=f"Authorization: {auth}\r\n"), ctx))

        creds = _events(events, "credentials")
        assert len(creds) == 1
        assert creds[0]["service"] == "rtsp"
        assert creds[0]["auth"] == "digest"
        assert creds[0]["username"] == "root"
        assert creds[0]["password"] is None
        assert creds[0]["realm"] == "IP Camera"
        assert creds[0]["nonce"] == "deadbeef"
        assert creds[0]["uri"] == "rtsp://cam/live.sdp"
        assert creds[0]["response"] == "8f3a1c2d4e5f60718293a4b5c6d7e8f9"
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 200 OK")

    def test_setup_issues_session_that_play_echoes(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(
            _req("SETUP", cseq=5,
                 extra="Transport: RTP/AVP;unicast;client_port=9000-9001\r\n"),
            ctx))
        setup_reply = bytes(writer.buffer)
        assert b"Transport: RTP/AVP;unicast;client_port=9000-9001" \
               b";server_port=6970-6971\r\n" in setup_reply

        session = ctx.state["session"]
        assert len(session) == 8
        assert f"Session: {session}\r\n".encode() in setup_reply

        writer.buffer.clear()
        _run(handler.on_data(_req("PLAY", cseq=6), ctx))
        play_reply = bytes(writer.buffer)
        assert play_reply.startswith(b"RTSP/1.0 200 OK")
        assert f"Session: {session}\r\n".encode() in play_reply
        assert b"RTP-Info: url=rtsp://cam/live.sdp/trackID=0" in play_reply

    def test_teardown_closes(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(_req("TEARDOWN", cseq=9), ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 200 OK")
        assert ctx.closed is True

    def test_pipelined_requests_get_two_replies(self):
        handler = _rtsp_handler()
        ctx, writer, events = _rtsp_session(handler)
        _run(handler.on_data(_req("OPTIONS", cseq=1) + _req("DESCRIBE", cseq=2),
                             ctx))
        reply = bytes(writer.buffer)
        assert reply.count(b"RTSP/1.0 ") == 2
        assert b"RTSP/1.0 200 OK" in reply
        assert b"RTSP/1.0 401 Unauthorized" in reply
        assert len(_events(events, "rtsp_request")) == 2

    def test_split_request_waits_for_terminator(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        blob = _req("OPTIONS", cseq=1)
        _run(handler.on_data(blob[:10], ctx))
        assert bytes(writer.buffer) == b""
        _run(handler.on_data(blob[10:], ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 200 OK")

    def test_set_parameter_body_is_consumed(self):
        handler = _rtsp_handler()
        ctx, writer, events = _rtsp_session(handler)
        body = b"barrier: on\r\n"
        blob = (b"SET_PARAMETER rtsp://cam/ RTSP/1.0\r\nCSeq: 7\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                + body + _req("OPTIONS", cseq=8))
        _run(handler.on_data(blob, ctx))
        methods = [e["method"] for e in _events(events, "rtsp_request")]
        assert methods == ["SET_PARAMETER", "OPTIONS"]

    def test_unknown_method_gets_501(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(_req("REGISTER"), ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 501 Not Implemented")

    def test_http_request_line_gets_400_and_close(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 400 Bad Request")
        assert ctx.closed is True

    def test_garbage_request_line_gets_400(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(b"\x00\x01\x02 junk\r\n\r\n", ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 400 Bad Request")
        assert ctx.closed is True

    def test_oversized_header_block_gets_400(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(b"OPTIONS rtsp://cam RTSP/1.0\r\nX: "
                             + b"A" * (64 * 1024 + 8), ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 400 Bad Request")
        assert ctx.closed is True

    def test_oversized_body_gets_400(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(b"ANNOUNCE rtsp://cam RTSP/1.0\r\nCSeq: 1\r\n"
                             b"Content-Length: 999999\r\n\r\n", ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 400 Bad Request")
        assert ctx.closed is True

    def test_bad_content_length_does_not_raise(self):
        handler = _rtsp_handler()
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(b"ANNOUNCE rtsp://cam RTSP/1.0\r\nCSeq: 1\r\n"
                             b"Content-Length: abc\r\n\r\n", ctx))
        assert bytes(writer.buffer).startswith(b"RTSP/1.0 400 Bad Request")

    def test_server_header_is_configurable(self):
        handler = _rtsp_handler(server="Dahua Rtsp Server")
        ctx, writer, _ = _rtsp_session(handler)
        _run(handler.on_data(_req("OPTIONS"), ctx))
        assert b"Server: Dahua Rtsp Server\r\n" in bytes(writer.buffer)

    def test_two_sessions_do_not_share_state(self):
        handler = _rtsp_handler()
        ctx_a, _, _ = _rtsp_session(handler)
        ctx_b, _, _ = _rtsp_session(handler)
        _run(handler.on_data(_req("SETUP"), ctx_a))
        _run(handler.on_data(_req("SETUP"), ctx_b))
        assert ctx_a.state["session"] != ctx_b.state["session"]
        assert ctx_a.state["nonce"] != ctx_b.state["nonce"]


# ---------- SOCKS ----------

def _socks_handler():
    return SocksHandler(ServiceConfig(
        port=1080, service_type="tcp", protocol="socks",
    ))


def _socks_session(handler):
    ctx, writer, events = _tcp_ctx()
    _run(handler.on_connect(ctx))
    return ctx, writer, events


def _socks5_domain_request(host: bytes, port: int, cmd: int = 1) -> bytes:
    return (bytes([0x05, cmd, 0x00, 0x03, len(host)]) + host
            + port.to_bytes(2, "big"))


class TestSocks5:
    def test_no_auth_end_to_end(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)

        _run(handler.on_data(b"\x05\x01\x00", ctx))
        assert bytes(writer.buffer) == b"\x05\x00"

        writer.buffer.clear()
        _run(handler.on_data(_socks5_domain_request(b"smtp.evil.test", 25), ctx))
        assert bytes(writer.buffer) == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"

        requests = _events(events, "proxy_request")
        assert len(requests) == 1
        assert requests[0] == {
            "version": 5, "command": "CONNECT",
            "dest_host": "smtp.evil.test", "dest_port": 25,
        }
        assert ctx.state["phase"] == "tunnel"
        assert ctx.closed is False

    def test_ipv4_and_ipv6_destinations(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        _run(handler.on_data(b"\x05\x01\x00", ctx))
        _run(handler.on_data(b"\x05\x01\x00\x01" + bytes([93, 184, 216, 34])
                             + (443).to_bytes(2, "big"), ctx))
        assert _events(events, "proxy_request")[0]["dest_host"] == "93.184.216.34"

        ctx6, _, events6 = _socks_session(handler)
        _run(handler.on_data(b"\x05\x01\x00", ctx6))
        raw = bytes.fromhex("20010db8000000000000000000000001")
        _run(handler.on_data(b"\x05\x01\x00\x04" + raw + (80).to_bytes(2, "big"),
                             ctx6))
        assert _events(events6, "proxy_request")[0]["dest_host"] == "2001:db8::1"

    def test_userpass_auth_emits_credentials(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)

        _run(handler.on_data(b"\x05\x02\x00\x02", ctx))
        assert bytes(writer.buffer) == b"\x05\x02"

        writer.buffer.clear()
        _run(handler.on_data(b"\x01\x04user\x04pa55", ctx))
        assert bytes(writer.buffer) == b"\x01\x00"

        creds = _events(events, "credentials")
        assert creds == [{"service": "socks5", "username": "user",
                          "password": "pa55"}]
        assert ctx.state["phase"] == "request5"

    def test_bind_and_udp_associate_command_names(self):
        for cmd, name in ((2, "BIND"), (3, "UDP_ASSOCIATE")):
            handler = _socks_handler()
            ctx, _, events = _socks_session(handler)
            _run(handler.on_data(b"\x05\x01\x00", ctx))
            _run(handler.on_data(
                _socks5_domain_request(b"a.test", 9999, cmd=cmd), ctx))
            assert _events(events, "proxy_request")[0]["command"] == name

    def test_request_split_across_three_chunks(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)
        frame = b"\x05\x01\x00" + _socks5_domain_request(b"checker.evil.test", 80)
        _run(handler.on_data(frame[:2], ctx))
        _run(handler.on_data(frame[2:9], ctx))
        assert _events(events, "proxy_request") == []
        _run(handler.on_data(frame[9:], ctx))

        requests = _events(events, "proxy_request")
        assert len(requests) == 1
        assert requests[0]["dest_host"] == "checker.evil.test"
        assert requests[0]["dest_port"] == 80
        assert bytes(writer.buffer).endswith(
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_bad_address_type_fails_and_closes(self):
        handler = _socks_handler()
        ctx, writer, _ = _socks_session(handler)
        _run(handler.on_data(b"\x05\x01\x00", ctx))
        writer.buffer.clear()
        _run(handler.on_data(b"\x05\x01\x00\x09\x00\x00", ctx))
        assert bytes(writer.buffer) == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
        assert ctx.closed is True

    def test_bad_command_fails(self):
        handler = _socks_handler()
        ctx, writer, _ = _socks_session(handler)
        _run(handler.on_data(b"\x05\x01\x00", ctx))
        writer.buffer.clear()
        _run(handler.on_data(_socks5_domain_request(b"a.test", 80, cmd=0x77),
                             ctx))
        assert bytes(writer.buffer).startswith(b"\x05\x01")
        assert ctx.closed is True


class TestSocks4:
    def test_socks4a_hostname_parsing(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)
        frame = (b"\x04\x01" + (587).to_bytes(2, "big")
                 + b"\x00\x00\x00\x2a" + b"scanbot\x00" + b"mail.evil.test\x00")
        _run(handler.on_data(frame, ctx))

        requests = _events(events, "proxy_request")
        assert requests == [{
            "version": 4, "command": "CONNECT",
            "dest_host": "mail.evil.test", "dest_port": 587,
            "userid": "scanbot",
        }]
        reply = bytes(writer.buffer)
        assert len(reply) == 8
        assert reply[:2] == b"\x00\x5a"
        assert reply[2:4] == (587).to_bytes(2, "big")
        assert reply[4:8] == b"\x00\x00\x00\x2a"
        assert ctx.state["phase"] == "tunnel"

    def test_socks4_plain_ip(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        frame = (b"\x04\x01" + (25).to_bytes(2, "big")
                 + bytes([203, 0, 113, 5]) + b"\x00")
        _run(handler.on_data(frame, ctx))
        requests = _events(events, "proxy_request")
        assert requests[0]["dest_host"] == "203.0.113.5"
        assert requests[0]["userid"] == ""

    def test_socks4_incomplete_waits(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)
        # No NUL terminator yet: nothing decided, nothing sent.
        _run(handler.on_data(b"\x04\x01\x00\x19\x00\x00\x00\x2auser", ctx))
        assert _events(events, "proxy_request") == []
        assert bytes(writer.buffer) == b""
        _run(handler.on_data(b"\x00host.test\x00", ctx))
        assert _events(events, "proxy_request")[0]["dest_host"] == "host.test"

    def test_socks4_bad_command_fails(self):
        handler = _socks_handler()
        ctx, writer, _ = _socks_session(handler)
        _run(handler.on_data(b"\x04\x09\x00\x19\x01\x02\x03\x04\x00", ctx))
        assert bytes(writer.buffer)[:2] == b"\x00\x5b"
        assert ctx.closed is True


class TestSocksTunnel:
    @staticmethod
    def _open_tunnel(handler, ctx):
        _run(handler.on_data(b"\x05\x01\x00", ctx))
        _run(handler.on_data(_socks5_domain_request(b"a.test", 80), ctx))

    def test_first_chunk_emits_payload_then_only_counts(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)
        self._open_tunnel(handler, ctx)
        writer.buffer.clear()

        _run(handler.on_data(b"hello\x00\xffworld", ctx))
        payloads = _events(events, "proxy_payload")
        assert len(payloads) == 1
        assert payloads[0]["bytes"] == 12
        assert payloads[0]["preview"] == "hello..world"
        assert ctx.state["tunnel_bytes"] == 12

        _run(handler.on_data(b"more", ctx))
        assert len(_events(events, "proxy_payload")) == 1
        assert ctx.state["tunnel_bytes"] == 16
        # We never reply to tunneled data.
        assert bytes(writer.buffer) == b""

    def test_preview_is_capped_at_200_bytes(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        self._open_tunnel(handler, ctx)
        _run(handler.on_data(b"A" * 500, ctx))
        payload = _events(events, "proxy_payload")[0]
        assert payload["bytes"] == 500
        assert len(payload["preview"]) == 200

    def test_http_connect_payload_is_attributed(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        self._open_tunnel(handler, ctx)
        _run(handler.on_data(b"CONNECT check.evil.test:443 HTTP/1.1\r\n"
                             b"Host: check.evil.test\r\n\r\n", ctx))
        assert _events(events, "proxy_http_request") == [
            {"method": "CONNECT", "target": "check.evil.test:443"},
        ]

    def test_http_get_payload_is_attributed(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        self._open_tunnel(handler, ctx)
        _run(handler.on_data(b"GET http://ip.evil.test/proxy-check HTTP/1.0\r\n"
                             b"\r\n", ctx))
        assert _events(events, "proxy_http_request")[0]["target"] == \
            "http://ip.evil.test/proxy-check"

    def test_non_http_payload_emits_no_http_event(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        self._open_tunnel(handler, ctx)
        _run(handler.on_data(b"EHLO evil.test\r\n", ctx))
        assert _events(events, "proxy_http_request") == []
        assert _events(events, "proxy_payload")

    def test_trailing_bytes_after_request_become_tunnel_payload(self):
        handler = _socks_handler()
        ctx, _, events = _socks_session(handler)
        _run(handler.on_data(b"\x05\x01\x00", ctx))
        _run(handler.on_data(
            _socks5_domain_request(b"a.test", 80) + b"GET / HTTP/1.1\r\n", ctx))
        assert _events(events, "proxy_payload")[0]["bytes"] == 16
        assert _events(events, "proxy_http_request")[0]["method"] == "GET"


class TestSocksGarbage:
    def test_unknown_version_closes_without_reply(self):
        handler = _socks_handler()
        ctx, writer, events = _socks_session(handler)
        _run(handler.on_data(b"\x16\x03\x01\x00\xa5", ctx))
        assert ctx.closed is True
        assert bytes(writer.buffer) == b""
        assert events == []

    @pytest.mark.parametrize("blob", [
        b"\x05",
        b"\x05\x00",
        b"\x05\x02\x00\x02\x01",
        b"\x05\x02\x00\x02\x01\x04us",
        b"\x05\x01\x00\x05\x01\x00\x03",
        b"\x04",
        b"\x04\x01\x00",
        b"\x04\x01\x00\x19\x00\x00\x00\x01",
        b"\x00" * 12,
        bytes(range(256)),
    ])
    def test_truncated_or_garbage_input_does_not_raise(self, blob):
        handler = _socks_handler()
        ctx, _, _ = _socks_session(handler)
        _run(handler.on_data(blob, ctx))

    def test_byte_at_a_time_garbage_does_not_raise(self):
        handler = _socks_handler()
        ctx, _, _ = _socks_session(handler)
        for byte in bytes(range(64)):
            _run(handler.on_data(bytes([byte]), ctx))

    def test_oversized_handshake_is_rejected(self):
        handler = _socks_handler()
        ctx, writer, _ = _socks_session(handler)
        # SOCKS4 userid that never terminates.
        _run(handler.on_data(b"\x04\x01\x00\x19\x00\x00\x00\x01"
                             + b"A" * 5000, ctx))
        assert bytes(writer.buffer)[:2] == b"\x00\x5b"
        assert ctx.closed is True

    def test_two_sessions_do_not_share_state(self):
        handler = _socks_handler()
        ctx_a, _, events_a = _socks_session(handler)
        ctx_b, _, events_b = _socks_session(handler)
        _run(handler.on_data(b"\x05\x01\x00", ctx_a))
        _run(handler.on_data(b"\x04\x01\x00\x19\x00\x00\x00\x01"
                             b"bot\x00h.test\x00", ctx_b))
        assert ctx_a.state["phase"] == "request5"
        assert ctx_b.state["phase"] == "tunnel"
        assert _events(events_a, "proxy_request") == []
        assert _events(events_b, "proxy_request")[0]["version"] == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
