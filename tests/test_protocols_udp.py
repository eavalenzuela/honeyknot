"""Tests for the Phase 3 UDP protocol handlers."""

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols import (
    ChargenHandler,
    DatagramContext,
    DNSHandler,
    MemcachedHandler,
    NetBIOSNSHandler,
    SNMPHandler,
    SSDPHandler,
)


class _FakeTransport:
    def __init__(self):
        self.sent: list[tuple[bytes, tuple]] = []
        self._closing = False

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append((data, addr))

    def close(self):
        self._closing = True

    def is_closing(self):
        return self._closing


def _udp_ctx(port: int = 0) -> tuple[DatagramContext, _FakeTransport]:
    t = _FakeTransport()
    ctx = DatagramContext(
        transport=t,
        addr=("10.0.0.5", 54321),
        port=port,
        request_logger=logging.getLogger("test.req"),
    )
    return ctx, t


def _cfg(protocol: str, **opts) -> ServiceConfig:
    return ServiceConfig(
        port=0, service_type="tcp", protocol=protocol,
        transport="udp", protocol_opts=opts,
    )


def _run(coro):
    return asyncio.run(coro)


def _dns_query(qname: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    labels = b""
    for part in qname.split("."):
        labels += bytes([len(part)]) + part.encode("ascii")
    labels += b"\x00"
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + labels + struct.pack(">HH", qtype, 1)


class TestDNS:
    def test_a_query_returns_answer(self):
        ctx, transport = _udp_ctx()
        handler = DNSHandler(_cfg("dns", answer_a="192.0.2.7"))
        _run(handler.on_datagram(_dns_query("evil.example"), ctx))
        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        assert reply[:2] == b"\x12\x34"  # txid echoed
        # Flags: QR=1 (high bit of byte 2)
        assert reply[2] & 0x80
        # Answer count = 1
        assert struct.unpack(">H", reply[6:8])[0] == 1
        # IP in answer
        assert bytes([192, 0, 2, 7]) in reply

    def test_query_logged(self, caplog):
        ctx, _ = _udp_ctx()
        handler = DNSHandler(_cfg("dns"))
        with caplog.at_level(logging.INFO, logger="honeyknot.protocols.dns"):
            _run(handler.on_datagram(_dns_query("foo.bar.baz"), ctx))
        assert any("foo.bar.baz" in r.message for r in caplog.records)

    def test_malformed_ignored(self):
        ctx, transport = _udp_ctx()
        handler = DNSHandler(_cfg("dns"))
        _run(handler.on_datagram(b"\x00" * 4, ctx))
        assert transport.sent == []


class TestSNMP:
    def test_community_extracted(self, caplog):
        ctx, _ = _udp_ctx()
        handler = SNMPHandler(_cfg("snmp"))
        # Minimal valid SEQUENCE { INTEGER version, OCTET STRING community, ... }
        community = b"public"
        pkt = (
            b"\x30" + bytes([3 + 2 + len(community)])
            + b"\x02\x01\x00"  # version INTEGER 0
            + b"\x04" + bytes([len(community)]) + community
        )
        with caplog.at_level(logging.INFO, logger="honeyknot.protocols.snmp"):
            _run(handler.on_datagram(pkt, ctx))
        assert any("public" in r.message for r in caplog.records)


class TestSSDP:
    def test_msearch_gets_reply(self):
        ctx, transport = _udp_ctx()
        handler = SSDPHandler(_cfg("ssdp"))
        _run(handler.on_datagram(
            b"M-SEARCH * HTTP/1.1\r\nST: upnp:rootdevice\r\n\r\n", ctx,
        ))
        assert len(transport.sent) == 1
        assert b"HTTP/1.1 200 OK" in transport.sent[0][0]

    def test_non_msearch_silent(self):
        ctx, transport = _udp_ctx()
        handler = SSDPHandler(_cfg("ssdp"))
        _run(handler.on_datagram(b"NOTIFY * HTTP/1.1\r\n\r\n", ctx))
        assert transport.sent == []


class TestNetBIOSNS:
    def test_name_decoded(self, caplog):
        ctx, _ = _udp_ctx()
        handler = NetBIOSNSHandler(_cfg("netbios_ns"))
        # Encode "WORKGROUP       " (15 chars padded + NUL suffix) via first-level
        name = b"WORKGROUP".ljust(15, b" ") + b"\x00"
        encoded = bytearray()
        for b in name:
            encoded.append(ord("A") + (b >> 4))
            encoded.append(ord("A") + (b & 0x0F))
        header = b"\x00" * 12
        pkt = header + bytes([32]) + bytes(encoded) + b"\x00"
        with caplog.at_level(logging.INFO, logger="honeyknot.protocols.netbios_ns"):
            _run(handler.on_datagram(pkt, ctx))
        assert any("WORKGROUP" in r.message for r in caplog.records)


class TestChargen:
    def test_reply_shorter_than_request(self):
        ctx, transport = _udp_ctx()
        handler = ChargenHandler(_cfg("chargen"))
        _run(handler.on_datagram(b"A" * 1500, ctx))
        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        assert len(reply) < 200


class TestMemcached:
    def test_probe_logged_silently(self, caplog):
        ctx, transport = _udp_ctx()
        handler = MemcachedHandler(_cfg("memcached"))
        frame = b"\x00\x01\x00\x00\x00\x01\x00\x00" + b"version\r\n"
        with caplog.at_level(logging.INFO, logger="honeyknot.protocols.memcached"):
            _run(handler.on_datagram(frame, ctx))
        assert transport.sent == []  # never replies — amplification defense
        assert any("version" in r.message for r in caplog.records)

    def test_undersized_ignored(self):
        ctx, transport = _udp_ctx()
        handler = MemcachedHandler(_cfg("memcached"))
        _run(handler.on_datagram(b"\x00" * 4, ctx))
        assert transport.sent == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
