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
        args.log_dir = 'logs/'
        args.log_max_bytes = 1048576
        args.log_backup_count = 5
        args.capture_limit = 4096
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

    # Configure loggers
    structured_logger = build_rotating_logger(
        f"port_{port_config}_structured",
        os.path.join(args.log_dir, f"{port_config}.jsonl"),
        args.log_max_bytes,
        args.log_backup_count,
    )
    error_logger = build_rotating_logger(
        f"port_{port_config}_errors",
        os.path.join(args.log_dir, f"{port_config}_errors.log"),
        args.log_max_bytes,
        args.log_backup_count,
    )
    capture_logger = build_rotating_logger(
        f"port_{port_config}_captures",
        os.path.join(args.log_dir, f"{port_config}_captures.log"),
        args.log_max_bytes,
        args.log_backup_count,
    )

    # Pre-load configuration for handler
    port_type, resp_dict, resp_headers, config_error = hk_handler.get_port_config_settings(port_config, args)
    if config_error:
        hk_handler.write_error(config_error, port_config, args, error_logger)
        return futures, config_error

    port_settings = (port_type, resp_dict, resp_headers)

    #####
    # hk_handler module thread-internal functions testing
    #####
    # hk_handler() function testing
    """
    dummy_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dummy_conn.bind((args.bind_ip, 9999))
    dummy_conn.listen(1)
    dummy_conn, addr = dummy_conn.accept()
    dc_data = dummy_conn.recv(2048)
    print(hk_handler.hk_handler(port_config, 'GET /huehuehue.php', dc_data, args))
    """
    # get_port_config_settings() function testing
    """
    print(hk_handler.get_port_config_settings(port_config, args))
    """
    #####

    # Create thread pool
    with ThreadPoolExecutor(int(args.thread_count)) as spte:
        # Create socket
        print('standing-up socket on '+str(socket_port)+'...')
        try:
            conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn_sock.bind((args.bind_ip, int(socket_port)))
        except Exception as se:
            print('socket construction error: ')
            print(se)
            sys.exit(1)
        futures = []
        for thread_num in range(int(args.thread_count)):
            if args.tv:
                print('|- running port handler '+str(port_config)+', thread '+str(thread_num))
            futures.append(
                spte.submit(
                    server_port_thread,
                    port_config,
                    thread_num,
                    None,
                    args,
                    port_settings,
                    structured_logger,
                    error_logger,
                    capture_logger,
                )
            )
        while True:
            # Move socket to listening
            while True:
                try:
                    conn_sock.listen(1)
                    break
                except Exception as e:
                    print('socket listen_state exception')
                    time.sleep(5)
                    continue

            # Grab idle thread
            if args.v:
                print('Grabbing idle thread for connection processing...')
            for future in as_completed(futures):
                if future.exception():
                    print(future.result())
                else:
                    thread_num = future.result()[0]
                    error_mssg = future.result()[1]
                    if args.tv:
                        print('|- spawning replacement port handler for '\
                                'str(port_config)'\
                                ', thread '+str(thread_num))
                    
                    # Feed incoming request to idle thread
                    while True:
                        try:
                            client_sock, client_address = conn_sock.accept()
                            break
                        except Exception as e:
                            time.sleep(5)
                            continue
                    print('connection from '+str(client_address)+' on port '+str(port_config))

                    client_info = [client_address, client_sock]
                    futures.append(
                        spte.submit(
                            server_port_thread,
                            port_config,
                            thread_num,
                            client_info,
                            args,
                            port_settings,
                            structured_logger,
                            error_logger,
                            capture_logger,
                        )
                    )
    hk_handler.write_error(error_mssg, port_config, args, error_logger)
    return futures, error_mssg

def build_rotating_logger(name, path, max_bytes, backup_count):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    handler = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger

def server_port_thread(port_config, thread_num, client_info, args, port_settings, structured_logger, error_logger, capture_logger):
    error_mssg = None
    print('|-- port handler: '+str(port_config)+', thread: '+str(thread_num))
    
    # If first run, return
    if client_info == None:
        hk_handler.write_error(error_mssg, port_config, args, error_logger)
        return thread_num, error_mssg
    else:
        client_address = client_info[0]
        client_connection = client_info[1]
        data = client_connection.recv(2048)
        if args.v:
            print(data)

    port_type, resp_dict, resp_headers = port_settings

    # Log capture with size limits (hex encoded)
    limited_data = data[: int(args.capture_limit)]
    capture_log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'src_ip': client_address[0],
        'src_port': client_address[1],
        'dest_port': port_config,
        'protocol': port_type,
        'capture_bytes': len(limited_data),
        'capture_truncated': len(data) > len(limited_data),
        'hex_dump': limited_data.hex(),
    }
    capture_logger.info(json.dumps(capture_log_entry))

    # Execute hk_handler
    matched_rule = None
    try:
        error_mssg, matched_rule, _ = hk_handler.hk_handler(
            port_config, data, client_connection, args, port_settings, error_logger
        )
        if args.v:
            print(error_mssg)
    except Exception as tk:
        tk = str(tk)
        error_mssg = 'server_port_thread(): '+tk

    # Structured log output
    structured_log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'src_ip': client_address[0],
        'src_port': client_address[1],
        'dest_port': port_config,
        'protocol': port_type,
        'matched_rule': matched_rule,
        'error': error_mssg,
    }
    structured_logger.info(json.dumps(structured_log_entry))

    hk_handler.write_error(error_mssg, port_config, args, error_logger)
    return thread_num, error_mssg

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--bind_ip', dest='bind_ip', help='IP address of interface to bind sockets to')
    parser.add_argument('--handler_directory', '-hd', dest='handler_dir', default='handlers/', help='path to folder containing files that define port handlers. See documentation for how to format handlers.')
    parser.add_argument('--definitions_directory', '-dd', dest='definition_dir', default='definition_files', help='path to folder containing service definiton json files')
    parser.add_argument('--log_directory', '-ld', dest='log_dir', default='logs/', help='path to folder to output log files to. Each service port will have its own logfile.')
    parser.add_argument('--log_max_bytes', dest='log_max_bytes', type=int, default=1048576, help='maximum size in bytes for a log file before rotation occurs (default 1MB).')
    parser.add_argument('--log_backup_count', dest='log_backup_count', type=int, default=5, help='number of rotated log files to retain (default 5).')
    parser.add_argument('--capture_limit', dest='capture_limit', type=int, default=4096, help='maximum number of bytes to capture per request for hex dumps (default 4096).')
    parser.add_argument('-v', action='store_true', default=False, help='enable verbose output')
    parser.add_argument('-tv', action='store_true', default=False, help='enable thread verbosity')
    parser.add_argument('-tc', '--thread_count', dest='thread_count', default=5, help='number of threads for each port process to manage (default 5)')
    args = parser.parse_args()

    # Ensure log directory exists
    os.makedirs(args.log_dir, exist_ok=True)

    # Call main loop-handler
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
