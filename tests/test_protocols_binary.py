"""Tests for the Phase 3 binary TCP handlers (SMB, MSSQL, RDP)."""

import asyncio
import logging
import struct

import pytest

from honeyknot.config import ServiceConfig
from honeyknot.protocols import ConnectionContext, MSSQLHandler, RDPHandler, SMBHandler


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


def _ctx(port: int = 0) -> tuple[ConnectionContext, _FakeWriter]:
    w = _FakeWriter()
    return ConnectionContext(
        writer=w, addr=("127.0.0.1", 54321), port=port,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
    ), w


def _cfg(protocol: str, **opts) -> ServiceConfig:
    return ServiceConfig(port=0, service_type="tcp", protocol=protocol,
                         protocol_opts=opts)


def _run(coro):
    return asyncio.run(coro)


class TestSMB:
    def test_negotiate_response(self):
        ctx, writer = _ctx()
        handler = SMBHandler(_cfg("smb"))
        # Build minimal SMB1 NEGOTIATE: header + word count 0 + bytecount 2 + "\x02NT LM 0.12\0"
        smb = bytearray(32)
        smb[0:4] = b"\xffSMB"
        smb[4] = 0x72  # NEGOTIATE
        smb += bytes([0])  # WordCount
        body = b"\x02NT LM 0.12\x00"
        smb += struct.pack("<H", len(body)) + body
        frame = b"\x00" + struct.pack(">I", len(smb))[1:] + bytes(smb)
        _run(handler.on_data(frame, ctx))
        assert writer.buffer[:4] == b"\x00\x00\x00\x00" or writer.buffer[0] == 0
        # Response starts with NBSS framing then SMB1 magic.
        assert b"\xffSMB" in writer.buffer
        # Word count byte should be 17 for NT LM 0.12 response
        # Locate the SMB header inside the NBSS frame
        smb_start = writer.buffer.index(b"\xffSMB")
        assert writer.buffer[smb_start + 32] == 17

    def test_closes_after_negotiate_and_next_frame(self):
        ctx, _ = _ctx()
        handler = SMBHandler(_cfg("smb"))
        neg_body = bytearray(32)
        neg_body[0:4] = b"\xffSMB"
        neg_body[4] = 0x72
        neg_body += bytes([0]) + struct.pack("<H", 0)
        neg_frame = b"\x00" + struct.pack(">I", len(neg_body))[1:] + bytes(neg_body)
        _run(handler.on_data(neg_frame, ctx))
        assert ctx.state.get("negotiated")
        # Second frame: SMB2 header — should trigger close.
        smb2 = bytes(64)
        smb2 = b"\xfeSMB" + smb2[4:]
        frame2 = b"\x00" + struct.pack(">I", len(smb2))[1:] + smb2
        _run(handler.on_data(frame2, ctx))
        assert ctx.closed


class TestMSSQL:
    @staticmethod
    def _tds(ptype: int, body: bytes) -> bytes:
        return struct.pack(">BBHHBB", ptype, 0x01, 8 + len(body), 0, 1, 0) + body

    def test_prelogin_response(self):
        ctx, writer = _ctx()
        handler = MSSQLHandler(_cfg("mssql"))
        pkt = self._tds(0x12, b"\xff")  # TDS_PRELOGIN + terminator
        _run(handler.on_data(pkt, ctx))
        assert writer.buffer[0] == 0x04  # TDS response
        assert b"\x0c\x00\x08" in writer.buffer  # SQL 12.0 version bytes

    def test_login7_triggers_error_and_close(self):
        ctx, writer = _ctx()
        handler = MSSQLHandler(_cfg("mssql"))
        pkt = self._tds(0x10, b"A" * 20)  # TDS_LOGIN7
        _run(handler.on_data(pkt, ctx))
        assert ctx.closed
        # Response contains ERROR token 0xAA
        assert 0xAA in writer.buffer

    def test_fragmented_packet(self):
        ctx, writer = _ctx()
        handler = MSSQLHandler(_cfg("mssql"))
        pkt = self._tds(0x12, b"\xff")
        _run(handler.on_data(pkt[:5], ctx))
        assert writer.buffer == b""  # not enough yet
        _run(handler.on_data(pkt[5:], ctx))
        assert len(writer.buffer) > 0


class TestRDP:
    def test_connection_request_confirmed(self):
        ctx, writer = _ctx()
        handler = RDPHandler(_cfg("rdp"))
        # Minimal X.224 CR wrapped in TPKT: TPKT(4) + X.224 header + RDP Neg Req
        rdp_neg = struct.pack("<BBHI", 0x01, 0x00, 8, 0x00000003)  # TYPE_RDP_NEG_REQ
        x224 = bytes([6 + len(rdp_neg), 0xE0, 0, 0, 0, 0, 0]) + rdp_neg
        tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
        _run(handler.on_data(tpkt, ctx))
        # Response: TPKT + X.224 Connection Confirm (0xD0) + neg response
        assert writer.buffer[0] == 3  # TPKT version
        assert 0xD0 in writer.buffer
        assert ctx.state.get("confirmed")

    def test_post_confirm_closes(self):
        ctx, writer = _ctx()
        handler = RDPHandler(_cfg("rdp"))
        rdp_neg = struct.pack("<BBHI", 0x01, 0x00, 8, 0x00000003)
        x224 = bytes([6 + len(rdp_neg), 0xE0, 0, 0, 0, 0, 0]) + rdp_neg
        tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
        _run(handler.on_data(tpkt, ctx))
        writer.buffer.clear()
        # Simulate TLS ClientHello arriving after confirm
        _run(handler.on_data(b"\x16\x03\x01\x00\xdc\x01\x00", ctx))
        assert ctx.closed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
