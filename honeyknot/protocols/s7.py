"""S7 honeypot on TCP/102 — Siemens PLC mimic for ICS recon attribution.

The stack is TPKT (RFC 1006) + COTP (ISO 8073) + S7comm. We do just enough:

  1. Answer COTP Connection Request with Connection Confirm.
  2. Reply to S7 Setup Communication with plausible PDU sizes.
  3. For Read-SZL 0x11/0x12 / Read/Write Var / any other S7 functions,
     log and return a minimal "Item not available" error so tools move
     on to the next fingerprint step without disconnecting early.
"""

from __future__ import annotations

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.s7")

TPKT_VERSION = 3
COTP_CR = 0xE0
COTP_CC = 0xD0
COTP_DT = 0xF0

S7_ROSCTR_JOB = 1
S7_ROSCTR_ACK_DATA = 3
S7_ROSCTR_USERDATA = 7


class S7Handler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", bytearray())
        ctx.state.setdefault("cotp_done", False)
        ctx.state["buffer"].extend(data)

        while len(ctx.state["buffer"]) >= 4 and not ctx.closed:
            if ctx.state["buffer"][0] != TPKT_VERSION:
                ctx.close()
                return
            length = struct.unpack(">H", ctx.state["buffer"][2:4])[0]
            if length < 7 or length > 65535:
                ctx.close()
                return
            if len(ctx.state["buffer"]) < length:
                return
            frame = bytes(ctx.state["buffer"][:length])
            ctx.state["buffer"] = ctx.state["buffer"][length:]
            await self._handle_tpkt(frame, ctx)

    async def _handle_tpkt(self, frame: bytes, ctx: ConnectionContext) -> None:
        if len(frame) < 7:
            return
        cotp_len = frame[4]
        cotp_code = frame[5]
        if cotp_code == COTP_CR:
            # CR layout: LI(1) code(1) dst_ref(2)=0 src_ref(2) class(1) params
            # CC's dst_ref must echo CR's src_ref so the client matches it.
            cr_src_ref = frame[8:10] if len(frame) >= 10 else b"\x00\x00"
            await ctx.send(_build_cotp_cc(cr_src_ref))
            ctx.state["cotp_done"] = True
            logger.info("S7 COTP CR from %s — confirmed", ctx.addr)
            return
        if cotp_code != COTP_DT or not ctx.state["cotp_done"]:
            return
        # S7 payload starts after the COTP header (cotp_len + 1 bytes)
        s7 = frame[4 + cotp_len + 1:]
        if len(s7) < 10 or s7[0] != 0x32:  # S7 protocol id
            return
        rosctr = s7[1]
        pdu_ref = s7[4:6]
        param_len = struct.unpack(">H", s7[6:8])[0]
        params = s7[10:10 + param_len]
        logger.info("S7 job from %s: rosctr=%d function=0x%02x",
                    ctx.addr,
                    rosctr,
                    params[0] if params else 0)
        ctx.event("s7_request",
                  rosctr=rosctr,
                  function=params[0] if params else 0,
                  params=params.hex())

        if rosctr != S7_ROSCTR_JOB or not params:
            return
        function = params[0]

        if function == 0xF0:  # Setup Communication
            await ctx.send(_build_s7_setup_ack(pdu_ref))
        elif function == 0x04 or function == 0x05:
            # Read Var / Write Var — respond with a "no such address" error
            # so the scanner sees a live responder without revealing data.
            await ctx.send(_build_s7_error(pdu_ref))
        else:
            # Unknown function: mimic a generic ack-data error.
            await ctx.send(_build_s7_error(pdu_ref))


def _build_cotp_cc(cr_src_ref: bytes) -> bytes:
    # CC: LI(1)=17, code(1)=0xD0, dst_ref(2)=echo of CR src_ref,
    # src_ref(2)=our own ref, class(1)=0, params.
    cotp = (
        bytes([17, COTP_CC])
        + cr_src_ref                   # dst ref = CR's src_ref
        + b"\x00\x01"                  # our src ref
        + b"\x00"                      # class/options
        + b"\xc0\x01\x0a"              # TPDU size = 1024
        + b"\xc1\x02\x01\x00"          # src-TSAP
        + b"\xc2\x02\x01\x02"          # dst-TSAP
    )
    total = 4 + len(cotp)
    return struct.pack(">BBH", TPKT_VERSION, 0, total) + cotp


def _build_s7_setup_ack(pdu_ref: bytes) -> bytes:
    # S7 header: protocol id=0x32, ROSCTR=Ack_Data(3), redundancy id 0,
    # PDU ref echoed, param len, data len, error class, error code
    param = b"\xf0\x00\x00\x03\x00\x03\x03\xc0"  # Setup Comm ack + PDU sizes
    s7 = struct.pack(">BBHHHHBB",
                     0x32, S7_ROSCTR_ACK_DATA, 0,
                     int.from_bytes(pdu_ref, "big"),
                     len(param), 0, 0, 0)
    s7 += param
    return _wrap_tpkt_dt(s7)


def _build_s7_error(pdu_ref: bytes) -> bytes:
    # Error class 0x85 (item addr error), code 0x01 (not available)
    param = b"\x00"  # minimal params
    s7 = struct.pack(">BBHHHHBB",
                     0x32, S7_ROSCTR_ACK_DATA, 0,
                     int.from_bytes(pdu_ref, "big"),
                     len(param), 0, 0x85, 0x01)
    s7 += param
    return _wrap_tpkt_dt(s7)


def _wrap_tpkt_dt(s7: bytes) -> bytes:
    cotp = bytes([2, COTP_DT, 0x80])
    total = 4 + len(cotp) + len(s7)
    return struct.pack(">BBH", TPKT_VERSION, 0, total) + cotp + s7
