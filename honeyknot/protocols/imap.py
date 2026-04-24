"""IMAP honeypot on TCP/143 — captures LOGIN credentials.

IMAP uses tagged commands: "<tag> CAPABILITY", "<tag> LOGIN user pass",
etc. The server speaks first with an untagged greeting. We advertise
PLAIN auth (via AUTH=PLAIN + LOGIN cmd both), accept one LOGIN attempt,
log it, then return NO "authentication failed" and drop. Non-LOGIN
commands get BAD to keep scanners from treading water.
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.imap")

GREETING = (
    b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS "
    b"ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN] honeyknot IMAP4 ready\r\n"
)


class IMAPHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        await ctx.send(GREETING)

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state["buffer"].extend(data)
        while b"\r\n" in ctx.state["buffer"]:
            line, _, rest = ctx.state["buffer"].partition(b"\r\n")
            ctx.state["buffer"] = bytearray(rest)
            await self._handle_line(bytes(line), ctx)
            if ctx.closed:
                return

    async def _handle_line(self, line: bytes, ctx: ConnectionContext) -> None:
        try:
            text = line.decode("utf-8", errors="replace").strip()
        except Exception:
            await ctx.send(b"* BAD protocol error\r\n")
            return
        if not text:
            return

        # AUTHENTICATE PLAIN continuation: next line is base64(\0user\0pass)
        pending = ctx.state.get("auth_pending")
        if pending is not None and ctx.state.get("auth_mech") == "PLAIN":
            ctx.state.pop("auth_pending", None)
            ctx.state.pop("auth_mech", None)
            import base64
            try:
                decoded = base64.b64decode(text).split(b"\x00")
                authzid = decoded[0].decode("utf-8", errors="replace") \
                    if len(decoded) > 0 else ""
                user = decoded[1].decode("utf-8", errors="replace") \
                    if len(decoded) > 1 else ""
                password = decoded[2].decode("utf-8", errors="replace") \
                    if len(decoded) > 2 else ""
            except Exception:
                authzid, user, password = "", "", text
            logger.info("IMAP AUTHENTICATE PLAIN from %s: "
                        "authzid=%r user=%r pass=%r",
                        ctx.addr, authzid, user, password)
            ctx.event("credentials", service="imap",
                      mechanism="PLAIN",
                      authzid=authzid, username=user, password=password)
            await ctx.send(
                f"{pending} NO [AUTHENTICATIONFAILED] "
                f"Invalid credentials\r\n".encode()
            )
            ctx.close()
            return

        parts = text.split(" ", 2)
        if len(parts) < 2:
            await ctx.send(f"{parts[0]} BAD Missing command\r\n".encode())
            return
        tag = parts[0]
        command = parts[1].upper()
        args = parts[2] if len(parts) > 2 else ""

        if command == "CAPABILITY":
            await ctx.send(
                b"* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR AUTH=PLAIN "
                b"AUTH=LOGIN\r\n"
            )
            await ctx.send(f"{tag} OK CAPABILITY completed\r\n".encode())
        elif command == "LOGIN":
            user, password = _split_login(args)
            logger.info("IMAP LOGIN from %s: user=%r pass=%r",
                        ctx.addr, user, password)
            ctx.event("credentials", service="imap",
                      username=user, password=password)
            await ctx.send(
                f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"
                .encode()
            )
            ctx.close()
        elif command == "AUTHENTICATE":
            mech = args.split(" ", 1)[0].upper() if args else ""
            if mech == "PLAIN":
                # RFC 4959: server sends '+ ' then client sends base64
                await ctx.send(b"+ \r\n")
                ctx.state["auth_pending"] = tag
                ctx.state["auth_mech"] = "PLAIN"
            else:
                await ctx.send(
                    f"{tag} NO Unsupported mechanism\r\n".encode()
                )
        elif command == "LOGOUT":
            await ctx.send(b"* BYE Logging out\r\n")
            await ctx.send(f"{tag} OK LOGOUT completed\r\n".encode())
            ctx.close()
        elif command == "STARTTLS":
            await ctx.send(f"{tag} NO STARTTLS not available\r\n".encode())
        elif command == "ID":
            await ctx.send(b'* ID ("name" "honeyknot")\r\n')
            await ctx.send(f"{tag} OK ID completed\r\n".encode())
        elif command == "NOOP":
            await ctx.send(f"{tag} OK NOOP completed\r\n".encode())
        else:
            await ctx.send(f"{tag} BAD Unknown command\r\n".encode())


def _split_login(args: str) -> tuple[str, str]:
    """LOGIN supports quoted strings; handle the simple cases."""
    if not args:
        return "", ""
    parts = _parse_quoted(args)
    if len(parts) < 2:
        return parts[0] if parts else "", ""
    return parts[0], parts[1]


def _parse_quoted(s: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    i = 0
    in_quotes = False
    while i < len(s):
        c = s[i]
        if in_quotes:
            if c == "\\" and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                out.append("".join(buf))
                buf = []
                in_quotes = False
                i += 1
                continue
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_quotes = True
            i += 1
            continue
        if c == " ":
            if buf:
                out.append("".join(buf))
                buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return out
