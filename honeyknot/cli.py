"""Command-line interface for honeyknot."""

import argparse

from honeyknot.logger import setup_logging
from honeyknot.server import HoneyknotDaemon


def main():
    parser = argparse.ArgumentParser(
        description="Honeyknot: a highly-configurable multi-port honeypot"
    )
    parser.add_argument(
        "-i", "--bind-ip", dest="bind_ip", required=True,
        help="IP address of interface to bind sockets to",
    )
    parser.add_argument(
        "-hd", "--handler-dir", dest="handler_dir", default="handlers/",
        help="path to directory containing TOML handler definitions "
             "(default: handlers/)",
    )
    parser.add_argument(
        "-ld", "--log-dir", dest="log_dir", default="logs/",
        help="path to directory for log output (default: logs/)",
    )
    parser.add_argument(
        "-tc", "--thread-count", dest="thread_count", type=int, default=5,
        help="number of threads per port process (default: 5)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="enable debug-level logging",
    )
    args = parser.parse_args()

    setup_logging(args.log_dir, verbose=args.verbose)

    daemon = HoneyknotDaemon(
        bind_ip=args.bind_ip,
        handler_dir=args.handler_dir,
        log_dir=args.log_dir,
        thread_count=args.thread_count,
    )
    daemon.start()


if __name__ == "__main__":
    main()
