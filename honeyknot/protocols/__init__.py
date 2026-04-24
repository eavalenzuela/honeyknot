"""Protocol handlers: per-connection state machines.

The base `ProtocolHandler` defines the lifecycle contract; concrete handlers
(regex, ssh, smtp, ...) subclass it. The server instantiates one handler
instance per port, shared across all connections on that port, and passes
per-connection state via a `ConnectionContext`.
"""

from honeyknot.config import ServiceConfig
from honeyknot.protocols.base import (
    ConnectionContext,
    DatagramContext,
    ProtocolHandler,
)
from honeyknot.protocols.chargen import ChargenHandler
from honeyknot.protocols.coap import CoAPHandler
from honeyknot.protocols.dns import DNSHandler
from honeyknot.protocols.ftp import FTPHandler
from honeyknot.protocols.http import HTTPHandler
from honeyknot.protocols.ipmi import IPMIHandler
from honeyknot.protocols.memcached import MemcachedHandler
from honeyknot.protocols.modbus import ModbusHandler
from honeyknot.protocols.mqtt import MQTTHandler
from honeyknot.protocols.mssql import MSSQLHandler
from honeyknot.protocols.mysql import MySQLHandler
from honeyknot.protocols.netbios_ns import NetBIOSNSHandler
from honeyknot.protocols.postgres import PostgresHandler
from honeyknot.protocols.rdp import RDPHandler
from honeyknot.protocols.redis import RedisHandler
from honeyknot.protocols.regex import RegexHandler
from honeyknot.protocols.sip import SIPHandler
from honeyknot.protocols.smb import SMBHandler
from honeyknot.protocols.smtp import SMTPHandler
from honeyknot.protocols.snmp import SNMPHandler
from honeyknot.protocols.ssdp import SSDPHandler
from honeyknot.protocols.ssh import SSHHandler
from honeyknot.protocols.telnet import TelnetHandler
from honeyknot.protocols.vnc import VNCHandler

__all__ = [
    "ChargenHandler",
    "CoAPHandler",
    "ConnectionContext",
    "DNSHandler",
    "DatagramContext",
    "FTPHandler",
    "HTTPHandler",
    "IPMIHandler",
    "MQTTHandler",
    "MSSQLHandler",
    "MemcachedHandler",
    "ModbusHandler",
    "MySQLHandler",
    "NetBIOSNSHandler",
    "PostgresHandler",
    "ProtocolHandler",
    "RDPHandler",
    "RedisHandler",
    "RegexHandler",
    "SIPHandler",
    "SMBHandler",
    "SMTPHandler",
    "SNMPHandler",
    "SSDPHandler",
    "SSHHandler",
    "TelnetHandler",
    "VNCHandler",
    "get_handler",
]

_REGISTRY: dict[str, type[ProtocolHandler]] = {
    "regex": RegexHandler,
    "ssh": SSHHandler,
    "smtp": SMTPHandler,
    "ftp": FTPHandler,
    "telnet": TelnetHandler,
    "redis": RedisHandler,
    "vnc": VNCHandler,
    "http": HTTPHandler,
    "dns": DNSHandler,
    "snmp": SNMPHandler,
    "ssdp": SSDPHandler,
    "netbios_ns": NetBIOSNSHandler,
    "chargen": ChargenHandler,
    "memcached": MemcachedHandler,
    "smb": SMBHandler,
    "mssql": MSSQLHandler,
    "rdp": RDPHandler,
    "sip": SIPHandler,
    "ipmi": IPMIHandler,
    "coap": CoAPHandler,
    "modbus": ModbusHandler,
    "mqtt": MQTTHandler,
    "mysql": MySQLHandler,
    "postgres": PostgresHandler,
}


def get_handler(config: ServiceConfig) -> ProtocolHandler:
    """Return the handler instance selected by config.protocol."""
    cls = _REGISTRY.get(config.protocol, RegexHandler)
    return cls(config)
