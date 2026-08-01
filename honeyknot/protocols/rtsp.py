"""RTSP honeypot on TCP/554 — the front door for IP-camera botnets.

Mirai/Hajime derivatives hammer RTSP with vendor-default credential lists,
so port 554 is one of the richest sources of live camera passwords on the
Internet. RTSP also leaks a model fingerprint for free: the request URL
(`/onvif/device_service`, `/live.sdp`, `/cam/realmonitor?channel=1`, `/11`)
tells you which vendor's exploit kit is knocking.

We play a cooperative camera. DESCRIBE without credentials gets a 401
offering both Digest and Basic, which pushes the scanner into handing over
whatever it has: Basic yields a cleartext user/pass, Digest yields an
offline-crackable response hash bound to the nonce we issued. Either way we
then answer 200 with a plausible SDP so the scanner walks on to SETUP and
PLAY, marks the host as owned, and reveals its whole session pattern.

Framing is HTTP-like text: `<METHOD> <url> RTSP/1.0\\r\\n<headers>\\r\\n\\r\\n`
with an optional Content-Length body (SET_PARAMETER / ANNOUNCE).
"""

from __future__ import annotations

import base64
import logging
import re
import secrets
from dataclasses import dataclass, field

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.rtsp")

HEADER_TERM = b"\r\n\r\n"
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 256 * 1024

DEFAULT_REALM = "IP Camera"
DEFAULT_SERVER = "Rtsp Server/2.0"

PUBLIC_METHODS = (
    "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, "
    "GET_PARAMETER, SET_PARAMETER"
)

# Methods that simply get an ack with the session id echoed back.
ACK_METHODS = {"GET_PARAMETER", "SET_PARAMETER", "PAUSE", "ANNOUNCE", "RECORD"}

# key="value" or key=value, comma separated (RFC 7616 auth-param list).
_AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')


@dataclass
class _Request:
    method: str
    url: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


class RTSPHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        # One nonce per session: the digest response the scanner computes is
        # only crackable if we remember the challenge we issued.
        ctx.state["nonce"] = secrets.token_hex(16)

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)

        while not ctx.closed:
            parsed = _try_parse(buf)
            if parsed is None:
                return  # need more bytes
            if parsed == "bad":
                buf.clear()
                await ctx.send(_response("400 Bad Request", None,
                                         self._server(), ["Connection: close"]))
                ctx.close()
                return
            consumed, request = parsed
            del buf[:consumed]
            await self._handle(request, ctx)

    def _server(self) -> str:
        return str(self.config.protocol_opts.get("server", DEFAULT_SERVER))

    def _realm(self) -> str:
        return str(self.config.protocol_opts.get("realm", DEFAULT_REALM))

    async def _handle(self, req: _Request, ctx: ConnectionContext) -> None:
        server = self._server()
        cseq = req.headers.get("cseq")
        user_agent = req.headers.get("user-agent", "")

        ctx.request_logger.info(
            "%s: RTSP %s %s cseq=%s ua=%r body=%dB",
            ctx.addr, req.method, req.url, cseq, user_agent, len(req.body),
        )
        ctx.event("rtsp_request", method=req.method, url=req.url,
                  cseq=cseq, user_agent=user_agent)

        method = req.method.upper()
        if method == "OPTIONS":
            await ctx.send(_response("200 OK", cseq, server,
                                     [f"Public: {PUBLIC_METHODS}"]))
        elif method == "DESCRIBE":
            await self._describe(req, cseq, ctx)
        elif method == "SETUP":
            session = _session_id(ctx)
            transport = req.headers.get(
                "transport", "RTP/AVP;unicast;client_port=8000-8001")
            await ctx.send(_response("200 OK", cseq, server, [
                f"Session: {session}",
                f"Transport: {transport};server_port=6970-6971",
            ]))
        elif method == "PLAY":
            session = _session_id(ctx)
            await ctx.send(_response("200 OK", cseq, server, [
                f"Session: {session}",
                f"RTP-Info: url={req.url}/trackID=0;seq=9810;rtptime=0",
            ]))
        elif method == "TEARDOWN":
            await ctx.send(_response("200 OK", cseq, server,
                                     [f"Session: {_session_id(ctx)}"]))
            ctx.close()
        elif method in ACK_METHODS:
            await ctx.send(_response("200 OK", cseq, server,
                                     [f"Session: {_session_id(ctx)}"]))
        else:
            await ctx.send(_response("501 Not Implemented", cseq, server))

    async def _describe(self, req: _Request, cseq: str | None,
                        ctx: ConnectionContext) -> None:
        server = self._server()
        realm = self._realm()
        scheme, _, param = req.headers.get("authorization", "").partition(" ")
        scheme = scheme.strip().lower()

        if scheme == "basic":
            username, password = _decode_basic(param.strip())
            logger.info("RTSP basic creds from %s: user=%r pass=%r",
                        ctx.addr, username, password)
            ctx.event("credentials", service="rtsp", auth="basic",
                      username=username, password=password)
        elif scheme == "digest":
            params = _parse_auth_params(param)
            logger.info("RTSP digest auth from %s: user=%r response=%r",
                        ctx.addr, params.get("username", ""),
                        params.get("response", ""))
            ctx.event("credentials", service="rtsp", auth="digest",
                      username=params.get("username", ""), password=None,
                      realm=params.get("realm", ""),
                      nonce=params.get("nonce", ""),
                      uri=params.get("uri", ""),
                      response=params.get("response", ""))
        else:
            # No (or unrecognised) credentials: challenge with both schemes so
            # the client picks whichever it can actually compute.
            nonce = _session_nonce(ctx)
            await ctx.send(_response("401 Unauthorized", cseq, server, [
                f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}"',
                f'WWW-Authenticate: Basic realm="{realm}"',
            ]))
            return

        # Credentials accepted on purpose: the scanner proceeds to SETUP/PLAY
        # and flags the host as owned, which is exactly the behaviour we farm.
        body = _sdp(req.url)
        await ctx.send(_response("200 OK", cseq, server, [
            "Content-Type: application/sdp",
            f"Content-Base: {req.url}/",
        ], body))


def _session_id(ctx: ConnectionContext) -> str:
    session = ctx.state.get("session")
    if not session:
        session = secrets.token_hex(4)
        ctx.state["session"] = session
    return session


def _session_nonce(ctx: ConnectionContext) -> str:
    nonce = ctx.state.get("nonce")
    if not nonce:
        nonce = secrets.token_hex(16)
        ctx.state["nonce"] = nonce
    return nonce


def _try_parse(buf: bytearray):
    """Parse one request from the head of buf.

    Returns (consumed, _Request), None when more bytes are needed, or the
    sentinel "bad" for anything we should answer with 400 and hang up on.
    """
    end = buf.find(HEADER_TERM)
    if end == -1:
        return "bad" if len(buf) > MAX_HEADER_BYTES else None
    if end > MAX_HEADER_BYTES:
        return "bad"

    header_block = bytes(buf[:end])
    body_start = end + len(HEADER_TERM)
    lines = header_block.split(b"\r\n")

    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) != 3:
        return "bad"
    method, url, version = parts
    if not version.upper().startswith("RTSP/"):
        # A generic scanner speaking HTTP (or noise) — not our protocol.
        return "bad"

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        headers[name.decode("latin-1").strip().lower()] = \
            value.decode("latin-1").strip()

    length = 0
    raw_length = headers.get("content-length")
    if raw_length:
        try:
            length = int(raw_length)
        except ValueError:
            return "bad"
        if length < 0 or length > MAX_BODY_BYTES:
            return "bad"
    if len(buf) < body_start + length:
        return None

    body = bytes(buf[body_start:body_start + length])
    return body_start + length, _Request(method, url, version, headers, body)


def _response(status: str, cseq: str | None, server: str,
              headers: list[str] | None = None, body: bytes = b"") -> bytes:
    lines = [f"RTSP/1.0 {status}"]
    if cseq is not None:
        lines.append(f"CSeq: {cseq}")
    lines.append(f"Server: {server}")
    if headers:
        lines.extend(headers)
    lines.append(f"Content-Length: {len(body)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")
    return head + body


def _decode_basic(param: str) -> tuple[str, str]:
    """Decode a Basic credential blob. Never raises on garbage."""
    try:
        raw = base64.b64decode(param + "=" * (-len(param) % 4))
    except Exception:
        return param, ""
    username, sep, password = raw.decode("utf-8", errors="replace").partition(":")
    if not sep:
        return username, ""
    return username, password


def _parse_auth_params(param: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _AUTH_PARAM_RE.finditer(param):
        key = match.group(1).lower()
        out[key] = match.group(2) if match.group(2) is not None else match.group(3)
    return out


def _sdp(url: str) -> bytes:
    """A small, plausible single-track H264 session description."""
    return (
        "v=0\r\n"
        "o=- 1109162014219182 0 IN IP4 0.0.0.0\r\n"
        "s=Media Presentation\r\n"
        "i=samsung\r\n"
        f"a=control:{url}\r\n"
        "t=0 0\r\n"
        "a=range:npt=now-\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "b=AS:4096\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 packetization-mode=1;profile-level-id=420029;"
        "sprop-parameter-sets=Z0IAKeKQFAe2AtwEBAaQeJEV,aM48gA==\r\n"
        "a=control:trackID=0\r\n"
    ).encode("latin-1", errors="replace")
