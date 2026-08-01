"""finger honeypot on TCP/79 — pure-signal user enumeration and relay bait.

Finger is nearly extinct, which makes any query to it a pure-signal event:
it is either an old mass-scanner, a user-enumeration attempt ahead of an
SSH brute force, or someone testing the host as a finger *relay*
(`user@victim`, the classic bounce). Cheap to serve, and the usernames
queried tell you exactly which credential list the attacker is working
from. Relay requests are logged and refused — we never forward anything.
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.finger")

DEFAULT_HOSTNAME = "srv01"
DEFAULT_USERS = (
    ("root", "root", "/bin/bash"),
    ("admin", "System Administrator", "/bin/bash"),
    ("deploy", "Deploy Service", "/bin/sh"),
)
MAX_QUERY = 1024  # cap on the query line

# Plausible tty/idle/login-time triples for the who-style listing.
_SESSIONS = (
    ("tty1", "2d", "Jul 29 09:14"),
    ("pts/0", "-", "Jul 30 22:03"),
    ("pts/1", "4:11", "Jul 30 07:52"),
)


class FingerHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        ctx.state["answered"] = False

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        if ctx.state.get("answered"):
            return
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)
        idx = buf.find(b"\n")
        if idx == -1:
            if len(buf) > MAX_QUERY:
                ctx.state["answered"] = True
                await ctx.send(b"finger: query too long\r\n")
                ctx.close()
            return
        if idx > MAX_QUERY:
            ctx.state["answered"] = True
            await ctx.send(b"finger: query too long\r\n")
            ctx.close()
            return
        raw = bytes(buf[:idx])
        del buf[:]
        ctx.state["answered"] = True
        # Sanitize before anything is echoed or logged: a hostile query
        # must not inject terminal escapes into a response or console.
        query = _sanitize(raw.decode("ascii", errors="replace").rstrip("\r"), MAX_QUERY)
        await self._answer(query, ctx)
        ctx.close()

    async def _answer(self, query: str, ctx: ConnectionContext) -> None:
        rest = query.strip()
        verbose = False
        if rest.startswith("/W"):
            verbose = True
            rest = rest[2:].strip()
        user = rest
        ctx.request_logger.info("%s: finger query %r verbose=%s", ctx.addr, query, verbose)
        ctx.event("finger_query", query=query, verbose=verbose, user=user)

        if "@" in rest:
            # Relay/bounce attempt (user@host). Refuse; never forward.
            target_host = rest.rsplit("@", 1)[1]
            logger.info("finger relay attempt from %s: %r", ctx.addr, query)
            ctx.event("finger_relay", query=query, target_host=target_host)
            await ctx.send(b"Finger forwarding service denied\r\n")
            return

        users = self._users()
        hostname = _sanitize(
            str(self.config.protocol_opts.get("hostname", DEFAULT_HOSTNAME)), 64)
        if not user:
            await ctx.send(_user_table(users, hostname))
        elif user in users:
            await ctx.send(_user_block(user, users[user], hostname))
        else:
            await ctx.send(f"finger: {user[:64]}: no such user.\r\n".encode())

    def _users(self) -> dict[str, dict]:
        raw = self.config.protocol_opts.get("users")
        users: dict[str, dict] = {}
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict) and entry.get("name"):
                    name = _sanitize(str(entry["name"]), 32)
                    users[name] = {
                        "fullname": _sanitize(str(entry.get("fullname", name)), 64),
                        "shell": _sanitize(str(entry.get("shell", "/bin/bash")), 64),
                    }
        if not users:
            users = {name: {"fullname": fullname, "shell": shell}
                     for name, fullname, shell in DEFAULT_USERS}
        return users


def _user_table(users: dict[str, dict], hostname: str) -> bytes:
    lines = [
        f"[{hostname}]",
        f"{'Login':<10}{'Name':<22}{'Tty':<8}{'Idle':<6}{'Login Time':<14}Office",
    ]
    for i, (name, info) in enumerate(users.items()):
        tty, idle, when = _SESSIONS[i % len(_SESSIONS)]
        lines.append(
            f"{name:<10}{info['fullname'][:20]:<22}{tty:<8}{idle:<6}{when:<14}")
    return ("\r\n".join(lines) + "\r\n").encode()


def _user_block(name: str, info: dict, hostname: str) -> bytes:
    home = "/root" if name == "root" else f"/home/{name}"
    lines = [
        f"[{hostname}]",
        f"Login: {name:<26} Name: {info['fullname']}",
        f"Directory: {home:<22} Shell: {info['shell']}",
        "Never logged in.",
        "No mail.",
        "No Plan.",
    ]
    return ("\r\n".join(lines) + "\r\n").encode()


def _sanitize(text: str, limit: int) -> str:
    """Keep printable ASCII only — no control chars, no escapes."""
    return "".join(ch for ch in text if 32 <= ord(ch) < 127)[:limit]
