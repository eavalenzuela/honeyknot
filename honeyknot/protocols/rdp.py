"""RDP honeypot on TCP/3389: respond to X.224 Connection Request with a
Connection Confirm, advertise SSL available, and capture whatever the
client sends next.

RDP starts with a TPKT-framed X.224 Connection Request carrying an
RDP Negotiation Request. We reply with a Connection Confirm + RDP
Negotiation Response selecting TLS (PROTOCOL_SSL). That gets us past the
"is anything there" probe stage and clients will typically proceed to
send their TLS ClientHello, which lands in the raw capture for tooling
fingerprinting.

We don't actually speak TLS afterwards — we just collect the bytes and
drop.
"""

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler
from honeyknot.tls_parse import extract_sni

logger = logging.getLogger("honeyknot.protocols.rdp")

TPKT_VERSION = 3
X224_CONNECTION_CONFIRM = 0xD0


class RDPHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", b"")
        ctx.state["buffer"] += data

        if not ctx.state.get("confirmed"):
            tpkt = _extract_tpkt(ctx.state["buffer"])
            if tpkt is None:
                return  # need more bytes
            frame, remainder = tpkt
            ctx.state["buffer"] = remainder
            logger.info("RDP X.224 CR from %s (%d bytes)", ctx.addr, len(frame))
            await ctx.send(_build_connection_confirm())
            ctx.state["confirmed"] = True
            return

        # After confirming, the next chunk is the TLS ClientHello or similar.
        # Try to pull SNI out of it before dropping.
        logger.info("RDP post-confirm data from %s: %d bytes",
                    ctx.addr, len(data))
        sni = extract_sni(data)
        if sni is not None:
            logger.info("RDP TLS SNI from %s: %r", ctx.addr, sni)
            ctx.event("tls_sni", source="rdp", sni=sni)
        ctx.close()


def _extract_tpkt(buf: bytes) -> tuple[bytes, bytes] | None:
    if len(buf) < 4:
        return None
    if buf[0] != TPKT_VERSION:
        return b"", b""  # malformed, force consume
    length = struct.unpack(">H", buf[2:4])[0]
    if length < 4 or length > 65535:
        return b"", b""
    if len(buf) < length:
        return None
    return buf[:length], buf[length:]


def _build_connection_confirm() -> bytes:
    # RDP Negotiation Response: type=2 (TYPE_RDP_NEG_RSP), flags=0,
    # length=8, selectedProtocol=1 (PROTOCOL_SSL)
    neg_rsp = struct.pack("<BBHI", 0x02, 0x00, 8, 0x00000001)
    # X.224 Connection Confirm: length-1 byte, code, dst-ref, src-ref, class.
    x224 = (
        bytes([6 + len(neg_rsp)])  # length indicator (length of X.224 TPDU - 1)
        + bytes([X224_CONNECTION_CONFIRM])
        + b"\x00\x00"  # dst ref
        + b"\x00\x00"  # src ref
        + b"\x00"      # class 0
        + neg_rsp
    )
    total = 4 + len(x224)
    tpkt = struct.pack(">BBH", TPKT_VERSION, 0, total)
    return tpkt + x224
