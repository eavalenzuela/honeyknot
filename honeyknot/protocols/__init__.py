"""Protocol handlers: per-connection state machines.

The base `ProtocolHandler` defines the lifecycle contract; concrete handlers
(regex, ssh, smtp, ...) subclass it. The server instantiates one handler
instance per port, shared across all connections on that port, and passes
per-connection state via a `ConnectionContext`.
"""

from honeyknot.config import ServiceConfig
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler
from honeyknot.protocols.ftp import FTPHandler
from honeyknot.protocols.redis import RedisHandler
from honeyknot.protocols.regex import RegexHandler
from honeyknot.protocols.smtp import SMTPHandler
from honeyknot.protocols.ssh import SSHHandler
from honeyknot.protocols.telnet import TelnetHandler

__all__ = [
    "ConnectionContext",
    "FTPHandler",
    "ProtocolHandler",
    "RedisHandler",
    "RegexHandler",
    "SMTPHandler",
    "SSHHandler",
    "TelnetHandler",
    "get_handler",
]

_REGISTRY: dict[str, type[ProtocolHandler]] = {
    "regex": RegexHandler,
    "ssh": SSHHandler,
    "smtp": SMTPHandler,
    "ftp": FTPHandler,
    "telnet": TelnetHandler,
    "redis": RedisHandler,
}


def get_handler(config: ServiceConfig) -> ProtocolHandler:
    """Return the handler instance selected by config.protocol."""
    cls = _REGISTRY.get(config.protocol, RegexHandler)
    return cls(config)
