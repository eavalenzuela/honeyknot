"""Request matching and response construction — pure logic, no I/O."""

import logging

from honeyknot.config import ServiceConfig

logger = logging.getLogger("honeyknot.handler")


def match_request(config: ServiceConfig, data: bytes) -> bytes:
    """Match incoming data against the service's rules and return the response.

    Tries each rule in order. Returns the first matching rule's response,
    or the default response if nothing matches, or empty bytes as last resort.
    """
    try:
        decoded = data.decode(config.encoding, errors="replace")
    except Exception:
        decoded = data.decode("utf-8", errors="replace")

    for rule in config.rules:
        if rule.pattern.search(decoded):
            logger.debug("Rule '%s' matched on port %d", rule.name, config.port)
            return build_response(config, rule.response)

    # No rule matched — send default response
    if config.default_response:
        logger.debug("No rule matched on port %d, sending default response",
                     config.port)
        return build_response(config, config.default_response)

    logger.debug("No rule matched on port %d, no default response configured",
                 config.port)
    return b""


def build_response(config: ServiceConfig, body: str) -> bytes:
    """Construct a full response, prepending HTTP headers if configured."""
    parts = []

    if config.response_headers:
        parts.append(config.response_headers.status_line)
        parts.extend(config.response_headers.headers)
        parts.append("")  # blank line separating headers from body

    parts.append(body)

    return "\r\n".join(parts).encode(config.encoding)
