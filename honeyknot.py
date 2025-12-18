import argparse
import configparser
import logging
import os
import sys
from typing import Iterable, List

import hk_handler
from service_runner import (
    MetricsClient,
    NullMetrics,
    NullThrottle,
    ProtocolHandler,
    ServiceRunner,
    ServiceScheduler,
    ThrottlePolicy,
)


class HoneyknotProtocolHandler(ProtocolHandler):
    """Adapters hk_handler into the ProtocolHandler interface."""

    def __init__(
        self,
        port_config: str,
        args: argparse.Namespace,
        *,
        logger: logging.Logger,
        metrics: MetricsClient,
    ) -> None:
        self.port_config = port_config
        self.args = args
        self.logger = logger
        self.metrics = metrics

    def handle_client(self, client_socket, client_address) -> None:
        try:
            data = client_socket.recv(2048)
            self._log_raw_request(client_address, data)
            error_mssg = hk_handler.hk_handler(self.port_config, data, client_socket, self.args)
            if error_mssg:
                self.logger.warning("%s reported error: %s", self.port_config, error_mssg)
                self.metrics.increment("honeyknot.handler.errors")
        finally:
            try:
                client_socket.close()
            except OSError:
                pass

    def _log_raw_request(self, client_address, data: bytes) -> None:
        os.makedirs(self.args.log_dir, exist_ok=True)
        logpath = os.path.join(self.args.log_dir, f"{self.port_config}.log")
        with open(logpath, "a") as rl:
            rl.write(f"{client_address}: {data}\n")
        self.metrics.increment("honeyknot.requests")


def run_from_interactive_shell(ip, use_custom_args, c_args):
    if use_custom_args:
        args = c_args
    else:
        class argContainer(object):
            pass

        args = argContainer()
        args.bind_ip = ip
        args.handler_dir = "handlers/"
        args.definition_dir = "definition_files/"
        args.thread_count = 5
        args.log_dir = "logs/"
        args.v = False
        args.tv = False
    main_loop(args)


def main_loop(args):
    logger = configure_logger(args)
    metrics = NullMetrics()
    throttle = NullThrottle()
    services = build_services(args, logger, metrics, throttle)
    scheduler = ServiceScheduler(max_workers=int(args.thread_count), logger=logger)
    scheduler.start(services)
    scheduler.wait()
    return scheduler


def build_services(
    args: argparse.Namespace,
    logger: logging.Logger,
    metrics: MetricsClient,
    throttle: ThrottlePolicy,
) -> List[ServiceRunner]:
    runners: List[ServiceRunner] = []
    for pc_file in get_port_config_files(args):
        port = resolve_port(pc_file, args)
        handler = HoneyknotProtocolHandler(pc_file, args, logger=logger, metrics=metrics)
        runners.append(
            ServiceRunner(
                args.bind_ip,
                port,
                handler,
                logger=logger,
                metrics=metrics,
                throttle=throttle,
            )
        )
    return runners


def resolve_port(port_config: str, args: argparse.Namespace) -> int:
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(args.handler_dir, str(port_config)))
    try:
        return int(cfg["main"]["port"])
    except Exception as exc:
        raise ValueError(f"Invalid port config for {port_config}") from exc


def configure_logger(args: argparse.Namespace) -> logging.Logger:
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "v", False) else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    return logging.getLogger("honeyknot")


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--bind_ip", dest="bind_ip", help="IP address of interface to bind sockets to")
    parser.add_argument(
        "--handler_directory",
        "-hd",
        dest="handler_dir",
        default="handlers/",
        help="path to folder containing files that define port handlers. See documentation for how to format handlers.",
    )
    parser.add_argument(
        "--definitions_directory",
        "-dd",
        dest="definition_dir",
        default="definition_files/",
        help="path to folder containing service definiton json files",
    )
    parser.add_argument(
        "--log_directory",
        "-ld",
        dest="log_dir",
        default="logs/",
        help="path to folder to output log files to. Each service port will have its own logfile.",
    )
    parser.add_argument("-v", action="store_true", default=False, help="enable verbose output")
    parser.add_argument("-tv", action="store_true", default=False, help="enable thread verbosity")
    parser.add_argument(
        "-tc",
        "--thread_count",
        dest="thread_count",
        default=5,
        help="maximum number of services to schedule concurrently (default 5)",
    )
    args = parser.parse_args()

    main_loop(args)


def get_port_config_files(args) -> Iterable[str]:
    try:
        files = []
        for (_, _, filenames) in os.walk(args.handler_dir):
            files.extend(filenames)
        if len(files) > 0:
            return files
        else:
            print("No configuration files found in target directory. Exiting.")
            sys.exit(1)
    except Exception as e:
        print(e)
        print("Configuration file enumeration failed. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    __spec__ = "ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>)"
    run()
