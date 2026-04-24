"""Tests for TLS SNI extractor, HTTP/2 preface event, raw-dir sweeper."""

import asyncio
import logging
import struct
import time

import pytest

from honeyknot.config import ResponseHeaders, ServiceConfig
from honeyknot.protocols import ConnectionContext, HTTPHandler, RDPHandler
from honeyknot.retention import _sweep_once
from honeyknot.tls_parse import extract_sni


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
    events: list = []
    ctx = ConnectionContext(
        writer=w, addr=("127.0.0.1", 54321), port=port,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, w, events


def _build_client_hello(sni: str | None) -> bytes:
    """Return a minimal TLS ClientHello record, with optional SNI extension."""
    version = b"\x03\x03"
    random_bytes = b"\x00" * 32
    session_id = b"\x00"
    cipher_suites = b"\x00\x02\x00\x2f"    # TLS_RSA_WITH_AES_128_CBC_SHA
    compression = b"\x01\x00"              # null compression

    extensions = b""
    if sni is not None:
        host = sni.encode("ascii")
        sni_ext_body = (b"\x00" + struct.pack(">H", len(host)) + host)
        sni_list = struct.pack(">H", len(sni_ext_body)) + sni_ext_body
        ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
        extensions = ext
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    hs_body = (version + random_bytes + session_id + cipher_suites
               + compression + extensions_block)
    hs = b"\x01" + struct.pack(">I", len(hs_body))[1:] + hs_body
    record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs
    return record


class TestSNIParser:
    def test_extracts_sni(self):
        pkt = _build_client_hello("evil.example")
        assert extract_sni(pkt) == "evil.example"

    def test_no_sni_returns_none(self):
        pkt = _build_client_hello(None)
        assert extract_sni(pkt) is None

    def test_non_tls_returns_none(self):
        assert extract_sni(b"GET / HTTP/1.1\r\n\r\n") is None
        assert extract_sni(b"") is None

    def test_truncated_returns_none(self):
        assert extract_sni(b"\x16\x03\x03") is None


class TestRDPSni:
    def test_rdp_emits_tls_sni_event(self):
        ctx, writer, events = _ctx()
        handler = RDPHandler(ServiceConfig(port=0, service_type="tcp",
                                           protocol="rdp"))

        rdp_neg = struct.pack("<BBHI", 0x01, 0x00, 8, 0x00000003)
        x224 = bytes([6 + len(rdp_neg), 0xE0, 0, 0, 0, 0, 0]) + rdp_neg
        tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
        asyncio.run(handler.on_data(tpkt, ctx))

        # Post-confirm: send a ClientHello carrying SNI.
        asyncio.run(handler.on_data(_build_client_hello("target.example"), ctx))
        sni_events = [e for e in events if e[0] == "tls_sni"]
        assert sni_events
        assert sni_events[0][1]["sni"] == "target.example"
        assert sni_events[0][1]["source"] == "rdp"


class TestH2Preface:
    def test_preface_emits_h2_event_and_505(self):
        ctx, writer, events = _ctx()
        handler = HTTPHandler(ServiceConfig(
            port=0, service_type="http", protocol="http",
            response_headers=ResponseHeaders(
                status_line="HTTP/1.1 200 OK", headers=[],
            ),
            default_response="ok",
        ))
        asyncio.run(handler.on_data(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nEXTRA", ctx,
        ))
        assert b"505 HTTP Version Not Supported" in writer.buffer
        assert ctx.closed
        assert any(e[0] == "h2_preface" for e in events)


class TestRawSweep:
    def test_under_cap_no_deletions(self, tmp_path):
        raw = tmp_path / "raw"
        raw.mkdir()
        (raw / "a.bin").write_bytes(b"x" * 100)
        (raw / "b.bin").write_bytes(b"x" * 100)
        deleted, total = _sweep_once(raw, max_bytes=500)
        assert deleted == 0
        assert total == 200

    def test_over_cap_evicts_oldest(self, tmp_path):
        raw = tmp_path / "raw"
        raw.mkdir()
        old = raw / "old.bin"
        old.write_bytes(b"x" * 200)
        # Make it older
        past = time.time() - 3600
        import os
        os.utime(old, (past, past))
        (raw / "new.bin").write_bytes(b"x" * 200)
        deleted, total = _sweep_once(raw, max_bytes=250)
        assert deleted == 1
        assert not old.exists()
        assert (raw / "new.bin").exists()
        assert total == 200

    def test_empty_dir_zero(self, tmp_path):
        raw = tmp_path / "raw"
        raw.mkdir()
        deleted, total = _sweep_once(raw, max_bytes=1)
        assert (deleted, total) == (0, 0)

    def test_missing_dir_zero(self, tmp_path):
        deleted, total = _sweep_once(tmp_path / "nope", max_bytes=1000)
        assert (deleted, total) == (0, 0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
