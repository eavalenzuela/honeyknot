"""HTTP protocol handler with proper body parsing.

Reads request line + headers, then consumes the entire body via
Content-Length or chunked transfer-encoding, and only then matches the
configured rules against the full request. This fixes two gaps in the
regex handler:

  1. Large POST/PUT bodies (>4KB) that arrive across multiple recv calls
     used to be truncated — now they're fully captured.
  2. Chunked uploads (common in webshell droppers) weren't decoded at all
     — now they are.

Per-request pipelining is supported: after responding, we loop back to
read the next request on the same connection, honoring Connection: close.
"""

import logging

from honeyknot.handler import match_request
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.http")

MAX_HEADER_BYTES = 64 * 1024  # reject oversized header blocks
MAX_BODY_BYTES = 10 * 1024 * 1024
HEADER_TERM = b"\r\n\r\n"


class HTTPHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", bytearray())
        ctx.state["buffer"].extend(data)

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

            ctx.request_logger.info(
                "%s: %s (body=%dB)", ctx.addr,
                request_bytes[:request_bytes.find(b"\r\n")], len(body),
            )
            ctx.event("http_request",
                      method=headers.get(":method"),
                      path=headers.get(":path"),
                      version=headers.get(":version"),
                      body_bytes=len(body),
                      content_type=headers.get("content-type"))

            response = match_request(self.config, request_bytes)
            if response:
                await ctx.send(response)

            # Honor Connection: close (or HTTP/1.0 default)
            close_requested = (
                headers.get("connection", "").lower() == "close"
                or headers.get(":version", "").startswith("HTTP/1.0")
            )
            if close_requested:
                ctx.close()
                return


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
