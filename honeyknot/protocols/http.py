"""HTTP protocol handler with body parsing, deception routes, and RCE capture.

Reads request line + headers, then consumes the entire body via
Content-Length or chunked transfer-encoding, and only then matches the
request. This fixes two gaps in the regex handler:

  1. Large POST/PUT bodies (>4KB) that arrive across multiple recv calls
     used to be truncated — now they're fully captured.
  2. Chunked uploads (common in webshell droppers) weren't decoded at all
     — now they are.

Per-request pipelining is supported: after responding, we loop back to
read the next request on the same connection, honoring Connection: close.

Response selection, in order:

  1. **Deception routes** (`honeyknot.deception`) — narrow, path-specific
     replies that make the host look exploitable: an `.env` full of canary
     credentials, a Docker API that accepts a container create, a `?cmd=`
     parameter answered from the shell emulator. These win over configured
     rules because they only fire on paths an operator is unlikely to have
     written a rule for, and because a plausible answer here is what buys
     the second stage. Set `[http] deception = false` to turn the layer off.
  2. **Configured `[[rules]]`** from the handler TOML.
  3. **`[default_response]`**.

Two other things happen per request regardless of which branch answers:
every request is run through `honeyknot.exploits` so the delivery vehicle
is recorded as an `exploit_attempt` event, and `CONNECT` is treated as
proxy abuse — we accept the tunnel and capture what the client sends
through it without ever connecting anywhere.
"""

import logging

from honeyknot.deception import DeceptionSite
from honeyknot.exploits import as_event_fields, classify
from honeyknot.handler import build_response, match_rule
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler
from honeyknot.shell import ShellSession

logger = logging.getLogger("honeyknot.protocols.http")

MAX_HEADER_BYTES = 64 * 1024  # reject oversized header blocks
MAX_BODY_BYTES = 10 * 1024 * 1024
HEADER_TERM = b"\r\n\r\n"
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_TUNNEL_PREVIEW = 200


class HTTPHandler(ProtocolHandler):
    def __init__(self, config):
        super().__init__(config)
        opts = config.protocol_opts or {}
        self.deception_enabled = bool(opts.get("deception", True))
        self.site = DeceptionSite(opts) if self.deception_enabled else None
        self.shell_opts = opts

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        # A CONNECT tunnel was accepted earlier in this session: everything
        # from here is the payload they meant to relay through us.
        if ctx.state.get("phase") == "tunnel":
            self._consume_tunnel(data, ctx)
            return

        ctx.state.setdefault("buffer", bytearray())
        ctx.state["buffer"].extend(data)

        # Distinct signal for h2 scanners — the HTTP/2 preface is not a
        # valid HTTP/1.1 request, and letting it fall through to 400 hides
        # a useful attribution.
        buf = bytes(ctx.state["buffer"])
        if buf.startswith(H2_PREFACE[:min(len(buf), len(H2_PREFACE))]) \
                and len(buf) >= len(H2_PREFACE):
            logger.info("HTTP/2 preface from %s", ctx.addr)
            ctx.event("h2_preface")
            await ctx.send(b"HTTP/1.1 505 HTTP Version Not Supported\r\n"
                           b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            ctx.close()
            return

        while not ctx.closed:
            result = _try_parse(ctx.state["buffer"])
            if result is None:
                return  # need more bytes
            if result == "oversized":
                await ctx.send(b"HTTP/1.1 413 Payload Too Large\r\n"
                               b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                ctx.close()
                return
            if result == "bad":
                await ctx.send(b"HTTP/1.1 400 Bad Request\r\n"
                               b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                ctx.close()
                return

            request_bytes, consumed, headers, body = result
            ctx.state["buffer"] = ctx.state["buffer"][consumed:]

            await self._handle_request(request_bytes, headers, body, ctx)
            if ctx.state.get("phase") == "tunnel":
                # Leftover bytes after the CONNECT are already tunnel payload.
                leftover = bytes(ctx.state["buffer"])
                ctx.state["buffer"] = bytearray()
                if leftover:
                    self._consume_tunnel(leftover, ctx)
                return

            # Honor Connection: close (or HTTP/1.0 default)
            close_requested = (
                headers.get("connection", "").lower() == "close"
                or headers.get(":version", "").startswith("HTTP/1.0")
            )
            if close_requested:
                ctx.close()
                return

    # -- per-request pipeline ---------------------------------------------

    async def _handle_request(self, request_bytes: bytes, headers: dict,
                              body: bytes, ctx: ConnectionContext) -> None:
        method = headers.get(":method", "")
        path = headers.get(":path", "")

        ctx.request_logger.info(
            "%s: %s (body=%dB)", ctx.addr,
            request_bytes[:request_bytes.find(b"\r\n")], len(body),
        )
        ctx.event("http_request",
                  method=method,
                  path=path,
                  version=headers.get(":version"),
                  body_bytes=len(body),
                  user_agent=headers.get("user-agent"),
                  content_type=headers.get("content-type"))

        hits = classify(request_bytes)
        if hits:
            logger.info("Exploit signature from %s: %s",
                        ctx.addr, [h["id"] for h in hits])
            ctx.event("exploit_attempt", method=method, path=path,
                      **as_event_fields(hits))

        if method == "CONNECT":
            await self._accept_tunnel(path, ctx)
            return

        response = await self._build_reply(method, path, headers, body,
                                           request_bytes, ctx)
        if response:
            await ctx.send(response)

    async def _build_reply(self, method: str, path: str, headers: dict,
                           body: bytes, request_bytes: bytes,
                           ctx: ConnectionContext) -> bytes:
        if self.site is not None:
            shell = self._session(ctx)
            web = self.site.respond(method, path, headers, body, shell)
            if web is not None:
                for name, fields in web.events:
                    if name == "_artifact":
                        ctx.artifact(fields["name"], fields["data"],
                                     kind="web_exec")
                        continue
                    ctx.event(name, **fields)
                if web.close:
                    ctx.close()
                return _render(web, headers.get(":version", "HTTP/1.1"),
                               self.site.server, head=(method == "HEAD"))

        matched = match_rule(self.config, request_bytes)
        if matched is not None:
            return build_response(self.config, matched)
        if self.config.default_response:
            return build_response(self.config, self.config.default_response)
        return b""

    def _session(self, ctx: ConnectionContext) -> ShellSession:
        """The per-connection shell, created on first use.

        Kept on `ctx.state` rather than the handler so two simultaneous
        attackers can't see each other's dropped files.
        """
        shell = ctx.state.get("shell")
        if shell is None:
            opts = self.shell_opts
            shell = ShellSession(
                hostname=opts.get("hostname", "srv-web-01"),
                user=opts.get("shell_user", "www-data"),
                arch=opts.get("arch", "x86_64"),
                opts=opts,
            )
            ctx.state["shell"] = shell
        return shell

    # -- CONNECT proxy abuse ----------------------------------------------

    async def _accept_tunnel(self, target: str, ctx: ConnectionContext) -> None:
        """Answer a CONNECT with success and capture the tunneled bytes.

        Open-proxy probing is a large share of internet background noise and
        the destination is high-signal: port 25/587 means a spam relay test,
        a vendor's own checker URL is a durable attribution artifact. We
        never connect anywhere — the tunnel goes to /dev/null and the bytes
        land in the session capture.
        """
        host, _, port = target.rpartition(":")
        ctx.event("proxy_request", version="http", command="CONNECT",
                  dest_host=host or target, dest_port=_safe_port(port))
        ctx.state["phase"] = "tunnel"
        ctx.state["tunnel_bytes"] = 0
        await ctx.send(b"HTTP/1.1 200 Connection established\r\n"
                       b"Proxy-Agent: nginx\r\n\r\n")

    def _consume_tunnel(self, data: bytes, ctx: ConnectionContext) -> None:
        total = ctx.state.get("tunnel_bytes", 0)
        if total == 0:
            ctx.event("proxy_payload", bytes=len(data),
                      preview=_preview(data))
        ctx.state["tunnel_bytes"] = total + len(data)
        ctx.request_logger.info("%s: tunnel +%dB (total %d)", ctx.addr,
                                len(data), ctx.state["tunnel_bytes"])


def _render(web, version: str, server: str, *, head: bool = False) -> bytes:
    """Serialize a WebResponse into an HTTP/1.1 reply."""
    version = version if version.startswith("HTTP/1.") else "HTTP/1.1"
    lines = [
        f"{version} {web.status}",
        f"Server: {server}",
        f"Content-Type: {web.content_type}",
        f"Content-Length: {len(web.body)}",
    ]
    lines.extend(web.extra_headers)
    lines.append("Connection: close" if web.close else "Connection: keep-alive")
    head_block = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
    return head_block if head else head_block + web.body


def _preview(data: bytes) -> str:
    text = data[:MAX_TUNNEL_PREVIEW].decode("latin-1")
    return "".join(c if 0x20 <= ord(c) < 0x7F else "." for c in text)


def _safe_port(raw: str) -> int | None:
    try:
        return int(raw)
    except ValueError:
        return None


def _try_parse(buf: bytearray):
    """Return (full_request_bytes, consumed, headers_dict, body) or a sentinel.

    Sentinels: None (need more bytes), "oversized", "bad".
    """
    end = buf.find(HEADER_TERM)
    if end == -1:
        if len(buf) > MAX_HEADER_BYTES:
            return "oversized"
        return None
    header_block = bytes(buf[:end])
    body_start = end + len(HEADER_TERM)

    try:
        first_line, *header_lines = header_block.split(b"\r\n")
        parts = first_line.decode("latin-1").split(" ", 2)
        if len(parts) != 3:
            return "bad"
        method, path, version = parts
        headers: dict[str, str] = {
            ":method": method, ":path": path, ":version": version,
        }
        for line in header_lines:
            name, _, value = line.partition(b":")
            if not name:
                continue
            headers[name.decode("latin-1").strip().lower()] = value.decode(
                "latin-1").strip()
    except (UnicodeDecodeError, ValueError):
        return "bad"

    # Body
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        body_result = _read_chunked(buf[body_start:])
        if body_result is None:
            return None
        body, body_consumed = body_result
        if body_consumed is False:
            return "bad"
    else:
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            return "bad"
        if length < 0 or length > MAX_BODY_BYTES:
            return "oversized"
        if len(buf) < body_start + length:
            return None
        body = bytes(buf[body_start:body_start + length])
        body_consumed = length

    consumed = body_start + body_consumed
    full_request = bytes(buf[:consumed])
    return full_request, consumed, headers, body


def _read_chunked(buf):
    """Decode HTTP/1.1 chunked transfer encoding.

    Returns (decoded_body, consumed_bytes) on success, None if incomplete,
    or (b"", False) on malformed input.
    """
    pos = 0
    decoded = bytearray()
    while True:
        line_end = buf.find(b"\r\n", pos)
        if line_end == -1:
            return None
        size_line = bytes(buf[pos:line_end]).split(b";", 1)[0]
        try:
            size = int(size_line, 16)
        except ValueError:
            return b"", False
        pos = line_end + 2
        if size == 0:
            # Optional trailer headers, then final CRLF
            trailer_end = buf.find(HEADER_TERM, pos - 2)
            if trailer_end != -1:
                pos = trailer_end + len(HEADER_TERM)
                return bytes(decoded), pos
            if buf[pos:pos + 2] == b"\r\n":
                return bytes(decoded), pos + 2
            return None
        if len(buf) < pos + size + 2:
            return None
        decoded.extend(buf[pos:pos + size])
        pos += size + 2  # trailing CRLF after chunk data
        if len(decoded) > MAX_BODY_BYTES:
            return b"", False
