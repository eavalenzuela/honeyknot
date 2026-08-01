"""SOCKS4/4a/5 honeypot on TCP/1080 — an open proxy that proxies nothing.

Open-proxy hunting is a permanent background hum on the Internet, and it is
unusually high-signal: the destination the client asks for states the intent
outright. Port 25/587 means a spam relay, a login host means credential
stuffing, and a request for the operator's own liveness-checker URL is a
durable attribution artifact — it names their infrastructure.

So we complete the handshake, report success, and then read whatever they
try to push through the tunnel without ever opening a socket of our own.
Username/password auth is accepted too, because a rejected proxy is a
forgotten proxy and we want them to keep talking.

Frames (all lengths guarded, attackers send truncated garbage constantly):
  SOCKS5 greeting  05 <nmethods> <methods...>
  SOCKS5 auth      01 <ulen> <user> <plen> <pass>
  SOCKS5 request   05 <cmd> 00 <atyp> <addr...> <port:2>
  SOCKS4 request   04 <cmd> <port:2> <ip:4> <userid> 00 [hostname 00]
"""

from __future__ import annotations

import ipaddress
import logging
import re

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.socks")

# A handshake this large is not a handshake.
MAX_HANDSHAKE_BYTES = 4096
PREVIEW_BYTES = 200

COMMANDS5 = {0x01: "CONNECT", 0x02: "BIND", 0x03: "UDP_ASSOCIATE"}
COMMANDS4 = {0x01: "CONNECT", 0x02: "BIND"}

AUTH_USERPASS = 0x02

# SOCKS5: version, rep=succeeded, rsv, atyp=IPv4, 0.0.0.0, port 0
REPLY5_OK = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
REPLY5_FAIL = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
# SOCKS4: null version byte, 0x5B = request rejected or failed
REPLY4_FAIL = b"\x00\x5b\x00\x00\x00\x00\x00\x00"

HTTP_LINE_RE = re.compile(r"^(GET|POST|HEAD|CONNECT) (\S+)")


class SocksHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        ctx.state["tunnel_bytes"] = 0

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)

        while buf and not ctx.closed:
            phase = ctx.state.get("phase")

            if phase is None:
                # Version is decided by the very first byte on the wire.
                if buf[0] == 0x05:
                    ctx.state["version"] = 5
                    ctx.state["phase"] = "greet5"
                elif buf[0] == 0x04:
                    ctx.state["version"] = 4
                    ctx.state["phase"] = "request4"
                else:
                    ctx.request_logger.info(
                        "%s: not SOCKS, first bytes hex=%s",
                        ctx.addr, bytes(buf[:16]).hex())
                    logger.info("Non-SOCKS client %s: %s",
                                ctx.addr, bytes(buf[:16]).hex())
                    ctx.close()
                    return
                continue

            if phase == "tunnel":
                chunk = bytes(buf)
                del buf[:]
                await _tunnel(chunk, ctx)
                return

            frame = bytes(buf)
            if phase == "greet5":
                consumed = await _greet5(frame, ctx)
            elif phase == "auth5":
                consumed = await _auth5(frame, ctx)
            elif phase == "request5":
                consumed = await _request5(frame, ctx)
            elif phase == "request4":
                consumed = await _request4(frame, ctx)
            else:  # pragma: no cover - defensive
                return

            if consumed <= 0:
                if len(buf) > MAX_HANDSHAKE_BYTES:
                    await _fail(ctx, "oversized handshake")
                return
            del buf[:consumed]


async def _greet5(buf: bytes, ctx: ConnectionContext) -> int:
    if len(buf) < 2:
        return 0
    nmethods = buf[1]
    if nmethods == 0:
        await _fail(ctx, "empty method list")
        return len(buf)
    if len(buf) < 2 + nmethods:
        return 0
    methods = buf[2:2 + nmethods]
    ctx.request_logger.info("%s: socks5 greeting methods=%s",
                            ctx.addr, methods.hex())
    if AUTH_USERPASS in methods:
        ctx.state["phase"] = "auth5"
        await ctx.send(bytes([0x05, AUTH_USERPASS]))
    else:
        ctx.state["phase"] = "request5"
        await ctx.send(b"\x05\x00")
    return 2 + nmethods


async def _auth5(buf: bytes, ctx: ConnectionContext) -> int:
    if len(buf) < 2:
        return 0
    if buf[0] != 0x01:
        await _fail(ctx, "bad auth version")
        return len(buf)
    ulen = buf[1]
    if len(buf) < 3 + ulen:
        return 0
    plen = buf[2 + ulen]
    end = 3 + ulen + plen
    if len(buf) < end:
        return 0
    username = buf[2:2 + ulen].decode("utf-8", errors="replace")
    password = buf[3 + ulen:end].decode("utf-8", errors="replace")

    ctx.request_logger.info("%s: socks5 auth user=%r pass=%r",
                            ctx.addr, username, password)
    logger.info("SOCKS5 creds from %s: user=%r pass=%r",
                ctx.addr, username, password)
    ctx.event("credentials", service="socks5",
              username=username, password=password)

    # Accepting keeps them talking; a rejected proxy gets dropped from the list.
    ctx.state["phase"] = "request5"
    await ctx.send(b"\x01\x00")
    return end


async def _request5(buf: bytes, ctx: ConnectionContext) -> int:
    if len(buf) < 4:
        return 0
    if buf[0] != 0x05:
        await _fail(ctx, "bad request version")
        return len(buf)
    cmd, atyp = buf[1], buf[3]

    if atyp == 0x01:
        need = 4 + 4 + 2
        if len(buf) < need:
            return 0
        host = ".".join(str(b) for b in buf[4:8])
    elif atyp == 0x03:
        if len(buf) < 5:
            return 0
        dlen = buf[4]
        need = 5 + dlen + 2
        if len(buf) < need:
            return 0
        host = buf[5:5 + dlen].decode("utf-8", errors="replace")
    elif atyp == 0x04:
        need = 4 + 16 + 2
        if len(buf) < need:
            return 0
        host = _format_ipv6(buf[4:20])
    else:
        await _fail(ctx, f"bad address type {atyp}")
        return len(buf)

    command = COMMANDS5.get(cmd)
    if command is None:
        await _fail(ctx, f"bad command {cmd}")
        return len(buf)
    port = int.from_bytes(buf[need - 2:need], "big")

    ctx.request_logger.info("%s: socks5 %s %s:%d",
                            ctx.addr, command, host, port)
    logger.info("SOCKS5 %s from %s to %s:%d", command, ctx.addr, host, port)
    ctx.event("proxy_request", version=5, command=command,
              dest_host=host, dest_port=port)

    ctx.state["phase"] = "tunnel"
    await ctx.send(REPLY5_OK)
    return need


async def _request4(buf: bytes, ctx: ConnectionContext) -> int:
    if len(buf) < 8:
        return 0
    cmd = buf[1]
    port = int.from_bytes(buf[2:4], "big")
    ip = buf[4:8]

    nul = buf.find(b"\x00", 8)
    if nul == -1:
        return 0
    userid = buf[8:nul].decode("utf-8", errors="replace")
    pos = nul + 1

    host = ".".join(str(b) for b in ip)
    # SOCKS4a: an unroutable 0.0.0.x address means a hostname follows.
    if ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] != 0:
        host_end = buf.find(b"\x00", pos)
        if host_end == -1:
            return 0
        host = buf[pos:host_end].decode("utf-8", errors="replace")
        pos = host_end + 1

    command = COMMANDS4.get(cmd)
    if command is None:
        await _fail(ctx, f"bad command {cmd}")
        return len(buf)

    ctx.request_logger.info("%s: socks4 %s %s:%d userid=%r",
                            ctx.addr, command, host, port, userid)
    logger.info("SOCKS4 %s from %s to %s:%d userid=%r",
                command, ctx.addr, host, port, userid)
    ctx.event("proxy_request", version=4, command=command,
              dest_host=host, dest_port=port, userid=userid)

    ctx.state["phase"] = "tunnel"
    # 0x5A = request granted; echo the port and address back.
    await ctx.send(b"\x00\x5a" + bytes(buf[2:8]))
    return pos


async def _tunnel(chunk: bytes, ctx: ConnectionContext) -> None:
    """Absorb payload the client believes is being relayed. Never reply."""
    total = ctx.state.get("tunnel_bytes", 0) + len(chunk)
    ctx.state["tunnel_bytes"] = total

    if ctx.state.get("tunnel_seen"):
        ctx.request_logger.info("%s: socks tunnel +%dB (total %dB) hex=%s",
                                ctx.addr, len(chunk), total, chunk[:16].hex())
        return

    ctx.state["tunnel_seen"] = True
    preview = _preview(chunk)
    ctx.request_logger.info(
        "%s: socks tunnel first chunk %dB hex=%s preview=%r",
        ctx.addr, len(chunk), chunk[:16].hex(), preview)
    ctx.event("proxy_payload", bytes=len(chunk), preview=preview)

    first_line = chunk.split(b"\n", 1)[0].decode("latin-1").strip()
    match = HTTP_LINE_RE.match(first_line)
    if match:
        logger.info("SOCKS tunnel HTTP %s %s from %s",
                    match.group(1), match.group(2), ctx.addr)
        ctx.event("proxy_http_request",
                  method=match.group(1), target=match.group(2))


async def _fail(ctx: ConnectionContext, reason: str) -> None:
    ctx.request_logger.info("%s: socks malformed frame (%s)", ctx.addr, reason)
    logger.info("SOCKS malformed frame from %s: %s", ctx.addr, reason)
    if ctx.state.get("version") == 4:
        await ctx.send(REPLY4_FAIL)
    else:
        await ctx.send(REPLY5_FAIL)
    ctx.close()


def _format_ipv6(raw: bytes) -> str:
    try:
        return ipaddress.IPv6Address(bytes(raw)).compressed
    except ValueError:
        return bytes(raw).hex()


def _preview(data: bytes) -> str:
    text = data[:PREVIEW_BYTES].decode("latin-1")
    return "".join(c if 32 <= ord(c) < 127 else "." for c in text)
