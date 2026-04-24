"""Regex-based protocol handler: replicates pre-asyncio one-shot behavior.

This is the back-compat handler. Every existing TOML runs under this: the
client speaks first, we match one regex against the first chunk, send one
response, then close. Payload analysis is handled by the server at
connection-close time against the full raw capture (see PortServer).
"""

import logging

from honeyknot.handler import match_request
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.regex")


class RegexHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        if ctx.state.get("responded"):
            return
        ctx.state["responded"] = True

        ctx.request_logger.info("%s: %s", ctx.addr, data)

        response = match_request(self.config, data)
        if response:
            await ctx.send(response)

        ctx.close()
