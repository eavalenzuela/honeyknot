"""TFTP honeypot on UDP/69 — capture RRQ/WRQ, refuse with an ERROR packet.

IoT/Mirai-class malware frequently fetches its next stage over TFTP; the
IOC extractor already flags `tftp` command lines seen in other captures.
This handler catches the server side: we log the requested filename and
transfer mode, emit a `tftp_request` event, then return a TFTP ERROR so the
client gives up quickly. We never serve a file and never amplify — the
ERROR reply is smaller than any real transfer.

RRQ/WRQ layout (RFC 1350):
    opcode(2)  1=RRQ 2=WRQ
    filename   NUL-terminated
    mode       NUL-terminated ("netascii" | "octet" | "mail")
    [options]  NUL-terminated key/value pairs (RFC 2347)
ERROR layout:
    opcode(2)=5  errcode(2)  message NUL-terminated
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.tftp")

OP_RRQ = 1
OP_WRQ = 2
OP_ERROR = 5
ERR_ACCESS_VIOLATION = 2


class TFTPHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 4:
            return
        opcode = int.from_bytes(data[:2], "big")
        if opcode not in (OP_RRQ, OP_WRQ):
            logger.info("TFTP non-request opcode=%d from %s", opcode, ctx.addr)
            return

        fields = data[2:].split(b"\x00")
        filename = fields[0].decode("utf-8", errors="replace") if fields else ""
        mode = (fields[1].decode("ascii", errors="replace")
                if len(fields) > 1 else "")
        op_name = "RRQ" if opcode == OP_RRQ else "WRQ"
        logger.info("TFTP %s %r (mode=%s) from %s",
                    op_name, filename, mode, ctx.addr)
        ctx.event("tftp_request", op=op_name, filename=filename, mode=mode)

        message = b"Access violation"
        error = (OP_ERROR.to_bytes(2, "big")
                 + ERR_ACCESS_VIOLATION.to_bytes(2, "big")
                 + message + b"\x00")
        ctx.send(error)
