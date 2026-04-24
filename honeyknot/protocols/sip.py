"""SIP honeypot on UDP/5060 — logs probes and VoIP credentials.

SIP is text-over-UDP. Scanners typically hit us with OPTIONS to fingerprint
the device, then REGISTER with fake credentials, then INVITE looking for
toll fraud. We respond with 401 Unauthorized + a canned nonce to REGISTER
so tools submit their Authorization: Digest response on the retry — which
gives us username + realm + nonce + response for offline cracking.
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.sip")

NONCE = "4c2cad11a40e2fbd25a4c52a9e3edf01"


class SIPHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        try:
            text = data.decode("ascii", errors="replace")
        except Exception:
            return
        first_line = text.split("\r\n", 1)[0]
        method = first_line.split(" ", 1)[0].upper() if first_line else ""
        headers = _parse_headers(text)
        from_hdr = headers.get("from", "")
        to_hdr = headers.get("to", "")
        ua = headers.get("user-agent", "")

        logger.info("SIP %s from %s: from=%r ua=%r",
                    method, ctx.addr, from_hdr[:80], ua[:80])
        ctx.event("sip_request",
                  method=method,
                  from_=from_hdr,
                  to=to_hdr,
                  user_agent=ua,
                  auth=headers.get("authorization", ""))

        if method not in ("OPTIONS", "REGISTER", "INVITE", "NOTIFY",
                          "MESSAGE", "SUBSCRIBE"):
            return

        via = headers.get("via", "SIP/2.0/UDP unknown")
        call_id = headers.get("call-id", "0")
        cseq = headers.get("cseq", "1 " + method)
        from_line = headers.get("from", f"<sip:unknown@{ctx.addr[0]}>")
        to_line = headers.get("to", f"<sip:honeyknot@{ctx.addr[0]}>")

        # If the client included Authorization digest data, accept and log it
        # as credential capture. Otherwise challenge with 401.
        if method in ("REGISTER", "INVITE") and "authorization" not in headers:
            reply = _build_response(
                "401 Unauthorized", via, from_line, to_line, call_id, cseq,
                extra=[
                    'WWW-Authenticate: Digest realm="honeyknot",'
                    f' nonce="{NONCE}", algorithm=MD5, qop="auth"',
                ],
            )
        elif method == "OPTIONS":
            reply = _build_response(
                "200 OK", via, from_line, to_line, call_id, cseq,
                extra=[
                    "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, "
                    "SUBSCRIBE, NOTIFY, REFER",
                    "Server: Asterisk PBX 16.0.0",
                ],
            )
        else:
            reply = _build_response(
                "200 OK", via, from_line, to_line, call_id, cseq,
            )
        ctx.send(reply.encode("ascii", errors="replace"))


def _parse_headers(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    lines = text.split("\r\n")
    for line in lines[1:]:
        if not line or line[0].isspace():
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        out[name.strip().lower()] = value.strip()
    return out


def _build_response(status: str, via: str, from_: str, to: str,
                    call_id: str, cseq: str,
                    extra: list[str] | None = None) -> str:
    lines = [
        f"SIP/2.0 {status}",
        f"Via: {via}",
        f"From: {from_}",
        f"To: {to}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
    ]
    if extra:
        lines.extend(extra)
    lines.append("Content-Length: 0")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines)
