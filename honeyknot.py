"""Honeyknot entrypoint.

This module wires together service loading, protocol handlers, and the
``ServiceRunner`` scheduler. It is intentionally minimal: the heavy lifting for
parsing schemas and handling requests lives in ``service_loader`` and
``hk_handler`` respectively.
"""

from __future__ import annotations

import argparse
import logging
import os
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Iterable, List

import hk_handler
from service_loader import ServiceDefinition, ServiceLoaderError, load_service_definitions
from service_runner import ServiceRunner, ServiceScheduler


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Honeyknot honeypot daemon")
    parser.add_argument("--bind-ip", "-i", dest="bind_ip", default=None, help="IP address to bind sockets to")
    parser.add_argument("--handler-directory", "-hd", dest="handler_dir", default="handlers", help="Legacy handler directory")
    parser.add_argument(
        "--definitions-directory",
        "-dd",
        dest="definition_dir",
        default="definition_files",
        help="Directory containing definition JSON files",
    )
    parser.add_argument(
        "--service_schema",
        "-ss",
        dest="service_schema",
        default=None,
        help="Path to a consolidated service schema (JSON or YAML)",
    )
    parser.add_argument(
        "--export_schema",
        "-es",
        dest="export_schema",
        default=None,
        help="Write a consolidated schema (JSON) from legacy handler files then exit",
    )
    parser.add_argument("--log_directory", "-ld", dest="log_dir", default="logs", help="Destination for log files")
    parser.add_argument(
        "--log_max_bytes", dest="log_max_bytes", type=int, default=1048576, help="Maximum log size before rotation"
    )
    parser.add_argument(
        "--log_backup_count", dest="log_backup_count", type=int, default=5, help="How many rotated logs to retain"
    )
    parser.add_argument(
        "--capture_limit",
        dest="capture_limit",
        type=int,
        default=4096,
        help="Maximum number of bytes per request to include in hex dumps",
    )
    parser.add_argument(
        "--processes",
        dest="processes",
        type=int,
        default=None,
        help="Number of worker processes (defaults to number of services)",
    )
    return parser.parse_args()


def _load_services(args: argparse.Namespace) -> List[ServiceDefinition]:
    services = load_service_definitions(args.service_schema, args.handler_dir, args.definition_dir, verbose=True)
    for service in services:
        if args.bind_ip:
            service.bind_ip = args.bind_ip
        elif not service.bind_ip:
            service.bind_ip = "0.0.0.0"
    return services


def _start_process(service: ServiceDefinition, args: argparse.Namespace) -> None:
    handler = hk_handler.handler_for_service(
        service,
        log_dir=args.log_dir,
        capture_limit=args.capture_limit,
        log_max_bytes=args.log_max_bytes,
        log_backup_count=args.log_backup_count,
    )
    runner = ServiceRunner(
        bind_ip=service.bind_ip,
        port=service.port,
        handler=handler,
        logger=logging.getLogger(f"runner.{service.port}"),
    )
    scheduler = ServiceScheduler(logger=logging.getLogger(f"scheduler.{service.port}"))
    scheduler.start([runner])
    scheduler.wait()


def _run_services(services: Iterable[ServiceDefinition], args: argparse.Namespace) -> None:
    workers = args.processes or len(services)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for service in services:
            executor.submit(partial(_start_process, service, args))


def main() -> None:
    args = _parse_args()
    os.makedirs(args.log_dir, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.export_schema:
        from service_loader import write_schema_from_handlers

        write_schema_from_handlers(args.handler_dir, args.definition_dir, args.export_schema)
        print(f"Legacy handler files exported to {args.export_schema}")
        return

    try:
        services = _load_services(args)
    except ServiceLoaderError as exc:
        raise SystemExit(str(exc))

    if not services:
        raise SystemExit("No services found. Provide a handler directory or schema.")

    _run_services(services, args)


if __name__ == "__main__":
    main()

