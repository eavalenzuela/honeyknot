"""TOML-based handler configuration loading and validation."""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Rule:
    """A pattern-matching rule: incoming data matching `pattern` gets `response`."""
    name: str
    pattern: re.Pattern
    response: str


@dataclass
class ResponseHeaders:
    """HTTP response headers to prepend to response bodies."""
    status_line: str
    headers: list[str] = field(default_factory=list)


@dataclass
class ServiceConfig:
    """Complete configuration for a single honeypot port."""
    port: int
    service_type: str  # "http", "https", "tcp"
    protocol: str = "regex"
    transport: str = "tcp"  # "tcp" or "udp"
    rules: list[Rule] = field(default_factory=list)
    response_headers: ResponseHeaders | None = None
    default_response: str = ""
    encoding: str = "utf-8"
    description: str = ""
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    protocol_opts: dict = field(default_factory=dict)


VALID_SERVICE_TYPES = {"http", "https", "tcp"}
VALID_PROTOCOLS = {
    "regex", "ssh", "smtp", "ftp", "telnet", "redis", "vnc", "http",
    "dns", "snmp", "ssdp", "netbios_ns", "chargen", "memcached",
    "smb", "mssql", "rdp",
    "sip", "ipmi", "coap",
    "modbus", "mqtt", "mysql", "postgres",
}
VALID_TRANSPORTS = {"tcp", "udp"}
UDP_PROTOCOLS = {"dns", "snmp", "ssdp", "netbios_ns", "chargen", "memcached",
                 "sip", "ipmi", "coap"}


def load_handler(path: Path) -> ServiceConfig:
    """Load and validate a TOML handler definition file.

    Raises ValueError on missing/invalid fields, including bad regex patterns.
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Validate [service] section
    if "service" not in data:
        raise ValueError(f"{path}: missing [service] section")

    svc = data["service"]
    if "port" not in svc:
        raise ValueError(f"{path}: missing service.port")

    if not isinstance(svc["port"], int):
        raise ValueError(f"{path}: service.port must be an integer")

    service_type = svc.get("type", "tcp")
    if service_type not in VALID_SERVICE_TYPES:
        raise ValueError(
            f"{path}: invalid service.type '{service_type}', "
            f"must be one of {VALID_SERVICE_TYPES}"
        )

    protocol = svc.get("protocol", "regex")
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(
            f"{path}: invalid service.protocol '{protocol}', "
            f"must be one of {VALID_PROTOCOLS}"
        )

    transport = svc.get("transport", "udp" if protocol in UDP_PROTOCOLS else "tcp")
    if transport not in VALID_TRANSPORTS:
        raise ValueError(
            f"{path}: invalid service.transport '{transport}', "
            f"must be one of {VALID_TRANSPORTS}"
        )
    if protocol in UDP_PROTOCOLS and transport != "udp":
        raise ValueError(
            f"{path}: protocol '{protocol}' requires transport = \"udp\""
        )

    # Protocol-specific opts live in a top-level section named after the protocol.
    # e.g. [ssh] banner = "...", [smtp] hostname = "..."
    protocol_opts = data.get(protocol, {}) if protocol != "regex" else {}

    # Compile regex patterns at load time
    rules = []
    for i, rule_data in enumerate(data.get("rules", [])):
        if "pattern" not in rule_data:
            raise ValueError(f"{path}: rule {i} missing 'pattern'")
        if "response" not in rule_data:
            raise ValueError(f"{path}: rule {i} missing 'response'")
        try:
            compiled = re.compile(rule_data["pattern"], re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"{path}: invalid regex in rule {i} "
                             f"({rule_data.get('name', '?')}): {e}") from e
        rules.append(Rule(
            name=rule_data.get("name", f"rule_{i}"),
            pattern=compiled,
            response=rule_data["response"],
        ))

    # Parse [response_headers] if present
    headers = None
    if "response_headers" in data:
        rh = data["response_headers"]
        if "status_line" not in rh:
            raise ValueError(f"{path}: response_headers missing 'status_line'")
        headers = ResponseHeaders(
            status_line=rh["status_line"],
            headers=rh.get("headers", []),
        )

    # Parse TLS config if present
    tls = data.get("tls", {})

    return ServiceConfig(
        port=svc["port"],
        service_type=service_type,
        protocol=protocol,
        transport=transport,
        description=svc.get("description", ""),
        rules=rules,
        response_headers=headers,
        default_response=data.get("default_response", {}).get("body", ""),
        encoding=svc.get("encoding", "utf-8"),
        tls_certfile=tls.get("certfile"),
        tls_keyfile=tls.get("keyfile"),
        protocol_opts=protocol_opts,
    )


def load_all_handlers(handler_dir: str | Path) -> list[ServiceConfig]:
    """Load all .toml handler files from a directory.

    Raises FileNotFoundError if no .toml files are found.
    """
    handler_dir = Path(handler_dir)
    if not handler_dir.is_dir():
        raise FileNotFoundError(f"Handler directory not found: {handler_dir}")

    configs = []
    for toml_file in sorted(handler_dir.glob("*.toml")):
        configs.append(load_handler(toml_file))

    if not configs:
        raise FileNotFoundError(
            f"No .toml handler files found in {handler_dir}"
        )

    return configs
