import ast
import configparser
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type


@dataclass
class ResponseRule:
    """A single request/response rule for a service."""

    match: str
    body: str
    headers: List[str] = field(default_factory=list)
    _compiled_regex: Optional[re.Pattern] = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        # Compilation happens lazily to allow caller to choose encoding.
        self._compiled_regex = None

    def _compile(self, encoding: str) -> None:
        if self._compiled_regex is None:
            try:
                self._compiled_regex = re.compile(
                    self.match.encode(encoding), re.IGNORECASE
                )
            except re.error as exc:  # pragma: no cover - defensive validation
                raise ServiceLoaderError(f"Invalid response rule regex: {self.match}") from exc

    def matches(self, data: bytes, encoding: str) -> bool:
        self._compile(encoding)
        payload = data if isinstance(data, bytes) else bytes(str(data), encoding=encoding)
        return bool(self._compiled_regex.match(payload))


@dataclass
class ServiceDefinition:
    """Represents a runnable service (HTTP or TCP) defined in the schema."""

    name: str
    protocol: str
    port: int
    bind_ip: str = "0.0.0.0"
    headers: List[str] = field(default_factory=list)
    responses: List[ResponseRule] = field(default_factory=list)
    encoding: str = "utf-8"

    def find_response(self, data: bytes) -> Optional[ResponseRule]:
        for rule in self.responses:
            if rule.matches(data, self.encoding):
                return rule
        return None


class HttpService(ServiceDefinition):
    protocol = "http"


class TcpService(ServiceDefinition):
    protocol = "tcp"


class ServiceLoaderError(Exception):
    pass


def _read_json_or_yaml(schema_path: str) -> Dict[str, Any]:
    _, ext = os.path.splitext(schema_path)
    with open(schema_path, "r") as schema_file:
        if ext.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore
            except ImportError as exc:
                raise ServiceLoaderError(
                    "PyYAML is required to read YAML service schemas"
                ) from exc
            return yaml.safe_load(schema_file)
        return json.load(schema_file)


def _normalize_pattern(match: str) -> str:
    pattern = match or ".*"
    if pattern.strip() in {"*", ""}:
        return ".*"
    return pattern


def _coerce_response_rules(raw_responses: List[Dict[str, Any]]) -> List[ResponseRule]:
    responses: List[ResponseRule] = []
    for resp in raw_responses:
        responses.append(
            ResponseRule(
                match=_normalize_pattern(resp.get("match", "")),
                body=resp.get("body", ""),
                headers=resp.get("headers", []),
            )
        )
    return responses


def _response_rules_from_legacy_definition(definition_path: str) -> List[ResponseRule]:
    with open(definition_path, "r") as def_file:
        raw = def_file.read()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = ast.literal_eval(raw)
    rules: List[ResponseRule] = []
    if not parsed:
        return rules
    comms = parsed.get("communication_dicts", [])
    for entry in comms:
        regex = _normalize_pattern(entry.get("regex", ""))
        response = entry.get("return", {}).get("value", "")
        rules.append(ResponseRule(match=regex, body=response))
    return rules


def _service_from_mapping(service_map: Dict[str, Any], default_bind_ip: Optional[str]) -> ServiceDefinition:
    service_type: Dict[str, Type[ServiceDefinition]] = {
        "http": HttpService,
        "tcp": TcpService,
    }
    listener = service_map.get("listener", {}) or {}
    bind_ip = listener.get("bind_ip") or default_bind_ip or "0.0.0.0"
    port = listener.get("port")
    if port is None:
        raise ServiceLoaderError("Service listener requires a port")
    protocol = service_map.get("protocol", "tcp").lower()
    service_class = service_type.get(protocol)
    if service_class is None:
        raise ServiceLoaderError(f"Unsupported protocol type: {protocol}")
    responses = _coerce_response_rules(service_map.get("responses", []))
    return service_class(
        name=service_map.get("name", f"service_{port}"),
        protocol=protocol,
        port=int(port),
        bind_ip=bind_ip,
        headers=service_map.get("headers", []),
        responses=responses,
        encoding=service_map.get("encoding", "utf-8"),
    )


def load_service_file(schema_path: str, default_bind_ip: Optional[str] = None) -> List[ServiceDefinition]:
    schema = _read_json_or_yaml(schema_path)
    if not isinstance(schema, dict):
        raise ServiceLoaderError("Service schema must be an object with a services list")
    if "services" not in schema:
        raise ServiceLoaderError("Service schema missing required 'services' list")
    services: List[ServiceDefinition] = []
    for svc in schema.get("services", []):
        services.append(_service_from_mapping(svc, default_bind_ip))
    return services


def load_handler_directory(handler_dir: str, definition_dir: str, verbose: bool = False) -> List[ServiceDefinition]:
    services: List[ServiceDefinition] = []
    for (_, _, filenames) in os.walk(handler_dir):
        for filename in filenames:
            cfp = configparser.ConfigParser()
            cfp.optionxform = str
            cfp.read(os.path.join(handler_dir, filename))
            if "main" not in cfp:
                continue
            port = int(cfp["main"].get("port"))
            protocol = cfp["main"].get("service_type", "tcp")
            headers = []
            responses: List[ResponseRule] = []
            if protocol == "http" and cfp.has_section("responses"):
                responses = [
                    ResponseRule(match=_normalize_pattern(pair[0]), body=pair[1])
                    for pair in cfp.items("responses")
                ]
                if cfp.has_section("response_headers"):
                    headers = [pair[1] for pair in cfp.items("response_headers")]
            if protocol != "http" and cfp.has_option("main", "definition_file"):
                def_path = os.path.join(definition_dir, cfp["main"]["definition_file"])
                responses = _response_rules_from_legacy_definition(def_path)
            service = ServiceDefinition(
                name=os.path.splitext(filename)[0],
                protocol=protocol,
                port=port,
                headers=headers,
                responses=responses,
            )
            services.append(service)
    if verbose:
        print(f"Loaded {len(services)} service(s) from handler files")
    return services


def load_service_definitions(
    schema_path: Optional[str], handler_dir: str, definition_dir: str, verbose: bool = False
) -> List[ServiceDefinition]:
    if schema_path and os.path.exists(schema_path):
        return load_service_file(schema_path)
    default_schema = os.path.join(definition_dir, "services.json")
    if os.path.exists(default_schema):
        return load_service_file(default_schema)
    return load_handler_directory(handler_dir, definition_dir, verbose)


def write_schema_from_handlers(
    handler_dir: str, definition_dir: str, output_path: str, default_bind_ip: str = "0.0.0.0"
) -> None:
    services = load_handler_directory(handler_dir, definition_dir)
    schema = {"services": []}
    for service in services:
        schema["services"].append(
            {
                "name": service.name,
                "protocol": service.protocol,
                "listener": {"port": service.port, "bind_ip": service.bind_ip or default_bind_ip},
                "headers": service.headers,
                "encoding": service.encoding,
                "responses": [
                    {"match": resp.match, "body": resp.body, "headers": resp.headers} for resp in service.responses
                ],
            }
        )
    with open(output_path, "w") as schema_file:
        json.dump(schema, schema_file, indent=2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Honeyknot service schema migration helper")
    parser.add_argument("--from-handlers", dest="handler_dir", help="Path to legacy handlers directory")
    parser.add_argument(
        "--definition-dir", dest="definition_dir", default="definition_files", help="Directory containing definition files"
    )
    parser.add_argument(
        "--output", dest="output_path", required=True, help="Where to write the consolidated service schema (JSON)"
    )
    args = parser.parse_args()
    if not args.handler_dir:
        raise SystemExit("--from-handlers is required when running the migration helper directly")
    write_schema_from_handlers(args.handler_dir, args.definition_dir, args.output_path)
    print(f"Wrote consolidated schema to {args.output_path}")
