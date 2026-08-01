"""rsync daemon honeypot on TCP/873 — module list bait + intent capture.

An open rsync daemon is a mass-data-exfiltration and mass-data-destruction
target, and the module list alone tells an attacker exactly what a host is
(backups, web roots, VM images). It is also routinely used to *push*
payloads onto hosts. The module list is cheap to fake, and the module name
the attacker asks for is a strong intent signal; the option list they send
after "auth" is even stronger — `--sender` means they are pulling data out
of the module, its absence means they are pushing files in. We answer the
plain-text daemon negotiation, harvest the challenge-auth username and
response, collect the NUL-separated argument vector, then let whatever
follows land in the raw capture.
"""

from __future__ import annotations

import logging
import secrets

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.rsync")

DEFAULT_VERSION = "31.0"
DEFAULT_MODULES = (
    ("backup", "Nightly server backups"),
    ("www", "Web root"),
    ("data", "Shared datasets"),
    ("media", "Media archive"),
)
MAX_LINE = 1024        # cap on a single negotiation line
MAX_BUFFER = 65536     # cap on total buffered bytes
MAX_ARGS = 50          # cap on collected argument entries
MAX_ARG_LEN = 200      # cap on a single argument's length


class RsyncHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        version = self.config.protocol_opts.get("version", DEFAULT_VERSION)
        ctx.state["buffer"] = bytearray()
        ctx.state["phase"] = "version"
        ctx.state["module"] = None
        ctx.state["args"] = []
        await ctx.send(f"@RSYNCD: {version}\n".encode())

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, bytes(data[:128]))
        if ctx.state.get("phase") == "post":
            # Past the checksum seed: the real binary protocol would start
            # here. We only farm the bytes — the raw capture keeps them.
            return
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)
        if len(buf) > MAX_BUFFER:
            await self._protocol_error(ctx)
            return
        while not ctx.closed:
            phase = ctx.state.get("phase")
            if phase == "post":
                del buf[:]
                return
            if phase == "args":
                progressed = await self._consume_arg(ctx)
            else:
                progressed = await self._consume_line(ctx)
            if not progressed:
                return

    # ---- line-oriented negotiation ----------------------------------

    async def _consume_line(self, ctx: ConnectionContext) -> bool:
        buf = ctx.state["buffer"]
        idx = buf.find(b"\n")
        if idx == -1:
            if len(buf) > MAX_LINE:
                await self._protocol_error(ctx)
            return False
        if idx > MAX_LINE:
            await self._protocol_error(ctx)
            return False
        raw = bytes(buf[:idx])
        del buf[:idx + 1]
        line = raw.decode("utf-8", errors="replace").rstrip("\r")
        phase = ctx.state.get("phase")
        if phase == "version":
            await self._handle_version(line, ctx)
        elif phase == "module":
            await self._handle_module(line, ctx)
        elif phase == "auth":
            await self._handle_auth(line, ctx)
        return True

    async def _handle_version(self, line: str, ctx: ConnectionContext) -> None:
        if line.startswith("@RSYNCD:"):
            ctx.state["client_version"] = _sanitize(line[len("@RSYNCD:"):].strip(), 40)
            ctx.state["phase"] = "module"
            return
        # Scanners often skip the version exchange and name a module (or
        # send garbage) straight away — fall through to module handling.
        ctx.state["phase"] = "module"
        await self._handle_module(line, ctx)

    async def _handle_module(self, line: str, ctx: ConnectionContext) -> None:
        if line.strip() in ("", "#list"):
            await self._send_module_list(ctx)
            return
        name = _sanitize(line.strip(), 100)
        modules = self._modules()
        known = name in modules
        logger.info("rsync module request from %s: %r known=%s", ctx.addr, name, known)
        ctx.event("rsync_module", module=name, known=known)
        if not known:
            await ctx.send(f"@ERROR: Unknown module '{name}'\n".encode())
            ctx.close()
            return
        ctx.state["module"] = name
        if self.config.protocol_opts.get("auth", True):
            challenge = secrets.token_urlsafe(16)
            ctx.state["challenge"] = challenge
            ctx.state["phase"] = "auth"
            await ctx.send(f"@RSYNCD: AUTHREQD {challenge}\n".encode())
        else:
            ctx.state["phase"] = "args"
            await ctx.send(b"@RSYNCD: OK\n")

    async def _handle_auth(self, line: str, ctx: ConnectionContext) -> None:
        parts = line.strip().split(None, 1)
        user = _sanitize(parts[0], 100) if parts else ""
        response = _sanitize(parts[1], 200) if len(parts) > 1 else ""
        logger.info("rsync auth from %s: user=%r", ctx.addr, user)
        ctx.event("credentials",
                  service="rsync",
                  username=user,
                  password=None,
                  auth="challenge",
                  challenge=ctx.state.get("challenge"),
                  response=response)
        ctx.state["phase"] = "args"
        await ctx.send(b"@RSYNCD: OK\n")

    async def _send_module_list(self, ctx: ConnectionContext) -> None:
        modules = self._modules()
        ctx.event("rsync_list", modules=list(modules))
        listing = "".join(f"{name}\t{comment}\n" for name, comment in modules.items())
        await ctx.send(listing.encode() + b"@RSYNCD: EXIT\n")
        ctx.close()

    # ---- argument collection ----------------------------------------

    async def _consume_arg(self, ctx: ConnectionContext) -> bool:
        buf = ctx.state["buffer"]
        idx = buf.find(b"\0")
        if idx == -1:
            return False
        raw = bytes(buf[:idx])
        del buf[:idx + 1]
        if raw == b"":
            # Empty argument terminates the vector.
            args = ctx.state.get("args", [])
            ctx.request_logger.info("%s: rsync args module=%s argc=%d",
                                    ctx.addr, ctx.state.get("module"), len(args))
            ctx.event("rsync_args", module=ctx.state.get("module"), args=args)
            ctx.state["phase"] = "post"
            # Checksum seed — the client expects 4 bytes before the binary
            # protocol starts. Any 4 bytes will do.
            await ctx.send(secrets.token_bytes(4))
            return True
        args = ctx.state.setdefault("args", [])
        if len(args) < MAX_ARGS:
            args.append(_sanitize(raw.decode("utf-8", errors="replace"), MAX_ARG_LEN))
        return True

    # ---- helpers ----------------------------------------------------

    def _modules(self) -> dict[str, str]:
        raw = self.config.protocol_opts.get("modules")
        out: dict[str, str] = {}
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict) and entry.get("name"):
                    out[_sanitize(str(entry["name"]), 100)] = str(entry.get("comment", ""))
        return out or dict(DEFAULT_MODULES)

    async def _protocol_error(self, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: rsync protocol error, closing", ctx.addr)
        await ctx.send(b"@ERROR: protocol startup error\n")
        ctx.close()


def _sanitize(text: str, limit: int) -> str:
    """Strip control / non-ASCII characters so attacker bytes can't be
    reflected into responses or an operator's console."""
    return "".join(ch for ch in text if 32 <= ord(ch) < 127)[:limit]
