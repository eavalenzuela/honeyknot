"""WS-Discovery honeypot on UDP/3702 — log Probes, no amplification.

WS-Discovery carries SOAP envelopes in UDP datagrams. Scanners (and
botnets preparing DDoS reflection) send Probe messages and expect
ProbeMatches. Our ProbeMatches is trimmed so the response is smaller
than the request, keeping us useless as an amplifier while still
showing up as "WS-Discovery" in recon.
"""

from __future__ import annotations

import logging
import re

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.wsd")

_ACTION_RE = re.compile(
    rb"<(?:[^:>]+:)?Action(?:\s[^>]*)?>([^<]+)</(?:[^:>]+:)?Action>",
    re.IGNORECASE,
)
_MSGID_RE = re.compile(
    rb"<(?:[^:>]+:)?MessageID(?:\s[^>]*)?>([^<]+)</(?:[^:>]+:)?MessageID>",
    re.IGNORECASE,
)


class WSDHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 16:
            return
        action_match = _ACTION_RE.search(data)
        msgid_match = _MSGID_RE.search(data)
        action = action_match.group(1).decode("utf-8", errors="replace") \
            if action_match else ""
        msg_id = msgid_match.group(1).decode("utf-8", errors="replace") \
            if msgid_match else ""
        logger.info("WS-Discovery probe from %s: action=%r msgid=%r",
                    ctx.addr, action[:120], msg_id[:120])
        ctx.event("wsd_probe", action=action, message_id=msg_id)

        if not action.endswith("Probe"):
            return

        body = _build_probematches(msg_id)
        if len(body) < len(data):
            ctx.send(body)


def _build_probematches(relates_to: str) -> bytes:
    """Minimal SOAP ProbeMatches envelope. Relates-To echoes the Probe MsgID."""
    relates = relates_to or "urn:uuid:00000000-0000-0000-0000-000000000000"
    env = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>"
        "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches"
        "</a:Action>"
        f"<a:RelatesTo>{relates}</a:RelatesTo>"
        "</s:Header>"
        "<s:Body><d:ProbeMatches/></s:Body>"
        "</s:Envelope>"
    )
    return env.encode("utf-8")
