"""Command-line interface for honeyknot."""

import argparse

from honeyknot import __version__
from honeyknot.config import UDP_PROTOCOLS, VALID_PROTOCOLS
from honeyknot.logger import setup_logging
from honeyknot.server import HoneyknotDaemon


class _ListProtocolsAction(argparse.Action):
    """`--list-protocols`: print the handler registry grouped by transport."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0,
                         default=argparse.SUPPRESS, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        udp = sorted(p for p in VALID_PROTOCOLS if p in UDP_PROTOCOLS)
        tcp = sorted(p for p in VALID_PROTOCOLS if p not in UDP_PROTOCOLS)
        print("Built-in protocol handlers:")
        print(f"  TCP ({len(tcp)}): " + ", ".join(tcp))
        print(f"  UDP ({len(udp)}): " + ", ".join(udp))
        parser.exit()


def main():
    parser = argparse.ArgumentParser(
        description="Honeyknot: a highly-configurable multi-port honeypot"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"honeyknot {__version__}",
    )
    parser.add_argument(
        "--list-protocols", action=_ListProtocolsAction,
        help="list the built-in protocol handlers grouped by transport, "
             "then exit",
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
    parser.add_argument(
        "--event-log-max-bytes", dest="event_log_max_bytes", type=int,
        default=None,
        help="rotate events.jsonl after this many bytes (default: 100MB)",
    )
    parser.add_argument(
        "--event-log-backups", dest="event_log_backups", type=int, default=None,
        help="number of rotated events.jsonl backups to keep (default: 10)",
    )
    parser.add_argument(
        "--rate-limit-capacity", dest="rate_limit_capacity", type=float,
        default=20.0,
        help="token bucket capacity per source IP; <=0 disables (default: 20)",
    )
    parser.add_argument(
        "--rate-limit-refill", dest="rate_limit_refill_per_sec", type=float,
        default=5.0,
        help="per-IP token refill rate in tokens/sec (default: 5)",
    )
    parser.add_argument(
        "--run-as-user", dest="run_as_user", default=None,
        help="switch to this unprivileged user after binding sockets",
    )
    parser.add_argument(
        "--run-as-group", dest="run_as_group", default=None,
        help="switch to this group after binding sockets",
    )
    parser.add_argument(
        "--yara-rules", dest="yara_rules", default=None,
        help="path to a .yar file or a directory of .yar/.yara files; "
             "requires yara-python",
    )
    parser.add_argument(
        "--pcap", dest="pcap_enabled", action="store_true", default=False,
        help="write per-session PCAP-ng files to logs/pcap/ alongside raw/",
    )
    parser.add_argument(
        "--metrics-bind", dest="metrics_bind", default=None,
        help="expose Prometheus metrics at host:port (e.g. 127.0.0.1:9099)",
    )
    parser.add_argument(
        "--raw-dir-max-bytes", dest="raw_dir_max_bytes", type=int, default=0,
        help="total byte cap for logs/raw/; oldest files deleted when "
             "exceeded. 0 (default) disables sweeping.",
    )
    parser.add_argument(
        "--conn-idle-timeout", dest="conn_idle_timeout", type=float,
        default=120.0,
        help="drop a TCP connection after this many seconds with no data; "
             "0 disables (default: 120)",
    )
    args = parser.parse_args()

    setup_logging(args.log_dir, verbose=args.verbose)

    daemon = HoneyknotDaemon(
        bind_ip=args.bind_ip,
        handler_dir=args.handler_dir,
        log_dir=args.log_dir,
        thread_count=args.thread_count,
        event_log_max_bytes=args.event_log_max_bytes,
        event_log_backups=args.event_log_backups,
        rate_limit_capacity=args.rate_limit_capacity,
        rate_limit_refill_per_sec=args.rate_limit_refill_per_sec,
        run_as_user=args.run_as_user,
        run_as_group=args.run_as_group,
        yara_rules=args.yara_rules,
        pcap_enabled=args.pcap_enabled,
        metrics_bind=args.metrics_bind,
        raw_dir_max_bytes=args.raw_dir_max_bytes,
        conn_idle_timeout=args.conn_idle_timeout,
    )
    daemon.start()


if __name__ == "__main__":
    main()
