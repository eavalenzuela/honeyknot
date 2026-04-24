"""DNS honeypot: parse queries, log them, return a canned A record.

Ransomware and droppers routinely do DNS lookups against attacker-controlled
resolvers. We don't want to be a useful resolver — but we do want to capture
what names are being looked up and by whom. We answer A queries with a
configurable canned address (default 127.0.0.1) so clients complete their
transaction and reveal their full intent.

Parses just enough of RFC 1035: header + first question (QNAME, QTYPE,
QCLASS). DNS compression pointers are not used in queries so we can skip
that hazard.
"""

import logging
import struct

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.dns")

QTYPE_A = 1
QTYPE_AAAA = 28


class DNSHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 12:
            return
        parsed = _parse_query(data)
        if parsed is None:
            return
        txid, qname, qtype, qclass, question_end = parsed
        logger.info("DNS query from %s: %s (type=%d)", ctx.addr, qname, qtype)

        answer_ip = self.config.protocol_opts.get("answer_a", "127.0.0.1")
        reply = _build_reply(data[:question_end], txid, qtype, qclass, answer_ip)
        if reply:
            ctx.send(reply)


def _parse_query(data: bytes):
    try:
        txid, flags, qdcount, _, _, _ = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return None
    if qdcount < 1:
        return None
    pos = 12
    labels = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:
            # Compression pointer in a query — unusual, bail.
            return None
        pos += 1
        if pos + length > len(data):
            return None
        labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
    pos += 4
    return txid, ".".join(labels), qtype, qclass, pos


def _build_reply(question_section: bytes, txid: int, qtype: int,
                 qclass: int, answer_ip: str) -> bytes:
    # Header: QR=1, AA=1, RD from request is irrelevant; set RA=1.
    flags = 0x8180
    ancount = 1 if qtype in (QTYPE_A, QTYPE_AAAA) else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, ancount, 0, 0)
    reply = header + question_section[12:]
    if ancount:
        # Answer: pointer to question name (c0 0c), type, class, TTL, RDLENGTH, RDATA
        if qtype == QTYPE_A:
            try:
                octets = bytes(int(o) for o in answer_ip.split("."))
                if len(octets) != 4:
                    return reply
            except ValueError:
                return reply
            reply += struct.pack(">HHHIH", 0xC00C, qtype, qclass, 60, 4) + octets
        elif qtype == QTYPE_AAAA:
            # Minimal ::1 answer
            rdata = b"\x00" * 15 + b"\x01"
            reply += struct.pack(">HHHIH", 0xC00C, qtype, qclass, 60, 16) + rdata
    return reply
