"""VNC honeypot: RFB 3.8 handshake with a fake-fail auth step.

Sequence:
  1. Server sends "RFB 003.008\n"
  2. Client replies with its version line (12 bytes, "\n"-terminated)
  3. Server advertises security types: [count=1][VNC_AUTH=2]
  4. Client sends the chosen type byte
  5. Server sends a 16-byte challenge (random-ish but deterministic here)
  6. Client sends a 16-byte DES-encrypted response — captured
  7. Server sends SecurityResult = 1 (failed) + reason string — drops

Attackers running credential stuffing on VNC will advance through all six
steps before realizing auth failed; we collect the encrypted response
block for offline analysis.
"""

import logging
import os

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.vnc")

SERVER_VERSION = b"RFB 003.008\n"
SECURITY_TYPE_VNC_AUTH = 2
FAIL_REASON = b"Authentication failed"


class VNCHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["phase"] = "await_version"
        ctx.state["buffer"] = b""
        ctx.state["challenge"] = os.urandom(16)
        await ctx.send(SERVER_VERSION)

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] += data
        while not ctx.closed:
            phase = ctx.state["phase"]
            if phase == "await_version":
                if len(ctx.state["buffer"]) < 12:
                    return
                client_version = bytes(ctx.state["buffer"][:12])
                ctx.state["buffer"] = ctx.state["buffer"][12:]
                logger.info("VNC client version from %s: %r",
                            ctx.addr, client_version)
                ctx.event("vnc_version", version=client_version.decode(
                    "ascii", errors="replace").rstrip("\n"))
                # Advertise VNC auth only.
                await ctx.send(bytes([1, SECURITY_TYPE_VNC_AUTH]))
                ctx.state["phase"] = "await_type_choice"
            elif phase == "await_type_choice":
                if len(ctx.state["buffer"]) < 1:
                    return
                chosen = ctx.state["buffer"][0]
                ctx.state["buffer"] = ctx.state["buffer"][1:]
                logger.info("VNC security type from %s: %d", ctx.addr, chosen)
                if chosen != SECURITY_TYPE_VNC_AUTH:
                    await self._send_fail(ctx)
                    return
                await ctx.send(ctx.state["challenge"])
                ctx.state["phase"] = "await_response"
            elif phase == "await_response":
                if len(ctx.state["buffer"]) < 16:
                    return
                response = bytes(ctx.state["buffer"][:16])
                ctx.state["buffer"] = ctx.state["buffer"][16:]
                logger.info("VNC auth response from %s: %s (challenge=%s)",
                            ctx.addr, response.hex(),
                            ctx.state["challenge"].hex())
                ctx.event("vnc_auth_attempt",
                          challenge=ctx.state["challenge"],
                          response=response)
                await self._send_fail(ctx)
                return
            else:
                ctx.close()
                return

    async def _send_fail(self, ctx: ConnectionContext) -> None:
        # SecurityResult = 1 (failed) as big-endian uint32
        await ctx.send(b"\x00\x00\x00\x01")
        # Reason length (u32) + reason bytes
        await ctx.send(len(FAIL_REASON).to_bytes(4, "big") + FAIL_REASON)
        ctx.close()
