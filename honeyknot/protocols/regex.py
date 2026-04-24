"""Regex-based protocol handler: replicates pre-asyncio one-shot behavior.

This is the back-compat handler. Every existing TOML runs under this: the
client speaks first, we match one regex against the first chunk, send one
response, run the analyzer on HTTP POST/PUT bodies, then close.
"""

import logging

from honeyknot.analyzer import analyze_payload
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

        self._try_analyze(data, ctx)
        ctx.close()

    def _try_analyze(self, data: bytes, ctx: ConnectionContext) -> None:
        try:
            decoded = data.decode("utf-8", errors="replace")
        except Exception:
            return

        if not (decoded.startswith("POST ") or decoded.startswith("PUT ")):
            return

        separator = b"\r\n\r\n"
        idx = data.find(separator)
        if idx == -1:
            return
        body = data[idx + len(separator):]
        if len(body) < 4:
            return

        result = analyze_payload(body)
        if result:
            logger.info("File analysis from %s: %s", ctx.addr, result)
