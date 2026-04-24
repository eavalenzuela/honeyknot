"""CoAP honeypot on UDP/5683 — IoT recon logger + ACK.

CoAP (RFC 7252) is a binary REST-ish protocol for constrained devices.
Scanners use GETs on /.well-known/core to enumerate endpoints. We parse
the header, reconstruct Uri-Path from the option list, log it, and return
a minimal 2.05 Content ack with a canned body so scanners register a
response and move on.

Header layout (4 bytes):
    Ver(2) | T(2) | TKL(4)
    Code(8)
    MessageID(16)
Then TKL bytes of token, then options (delta-encoded), optional 0xFF + payload.
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.coap")

URI_PATH_OPTION = 11


class CoAPHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 4:
            return
        ver = (data[0] >> 6) & 0x03
        msg_type = (data[0] >> 4) & 0x03
        tkl = data[0] & 0x0F
        code = data[1]
        msg_id = int.from_bytes(data[2:4], "big")
        if ver != 1 or tkl > 8 or 4 + tkl > len(data):
            logger.info("CoAP malformed from %s (len=%d)", ctx.addr, len(data))
            return
        token = data[4:4 + tkl]
        uri_path = _parse_uri_path(data[4 + tkl:])
        method = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE"}.get(
            code, f"code={code}")
        logger.info("CoAP %s /%s from %s (msgid=0x%04x)",
                    method, uri_path, ctx.addr, msg_id)
        ctx.event("coap_request",
                  method=method, path=uri_path,
                  msg_id=msg_id, token=token.hex())

        # Only answer Confirmable (type=0) requests; Non-confirmable (type=1)
        # gets nothing. Return 2.05 Content ack with a tiny payload.
        if msg_type != 0:
            return
        payload = b"hk"
        # Ver=1, T=2 (ACK), TKL same as request
        header0 = (1 << 6) | (2 << 4) | tkl
        response = bytes([header0, 0x45])  # 0x45 = 2.05 Content
        response += data[2:4]               # echo message ID
        response += token
        response += b"\xff" + payload
        ctx.send(response)


def _parse_uri_path(body: bytes) -> str:
    parts: list[str] = []
    pos = 0
    current_option = 0
    while pos < len(body):
        b = body[pos]
        if b == 0xFF:  # payload marker
            break
        delta = (b >> 4) & 0x0F
        length = b & 0x0F
        pos += 1
        if delta == 13:
            if pos >= len(body):
                return "/".join(parts)
            delta = body[pos] + 13
            pos += 1
        elif delta == 14:
            if pos + 2 > len(body):
                return "/".join(parts)
            delta = int.from_bytes(body[pos:pos + 2], "big") + 269
            pos += 2
        elif delta == 15:
            return "/".join(parts)
        current_option += delta
        if length == 13:
            if pos >= len(body):
                return "/".join(parts)
            length = body[pos] + 13
            pos += 1
        elif length == 14:
            if pos + 2 > len(body):
                return "/".join(parts)
            length = int.from_bytes(body[pos:pos + 2], "big") + 269
            pos += 2
        elif length == 15:
            return "/".join(parts)
        if pos + length > len(body):
            return "/".join(parts)
        value = body[pos:pos + length]
        pos += length
        if current_option == URI_PATH_OPTION:
            parts.append(value.decode("utf-8", errors="replace"))
    return "/".join(parts)
