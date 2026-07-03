"""Honeyknot: A highly-configurable multi-port honeypot for farming malware."""

__version__ = "0.4.0"


def run_from_interactive_shell(ip, handler_dir="handlers/", log_dir="logs/",
                               verbose=False, **daemon_kwargs):
    """Start honeyknot from a Python interactive shell.

    Args:
        ip: IP address to bind sockets to.
        handler_dir: Path to directory containing TOML handler definitions.
        log_dir: Path to directory for log output.
        verbose: Enable debug-level logging.
        **daemon_kwargs: Any ``HoneyknotDaemon`` option, forwarded verbatim —
            e.g. ``rate_limit_capacity``, ``rate_limit_refill_per_sec``,
            ``yara_rules``, ``pcap_enabled``, ``metrics_bind``,
            ``raw_dir_max_bytes``, ``conn_idle_timeout``. (``thread_count``
            is still accepted for back-compat but ignored under asyncio.)
    """
    from honeyknot.logger import setup_logging
    from honeyknot.server import HoneyknotDaemon

    setup_logging(log_dir, verbose=verbose)
    daemon = HoneyknotDaemon(
        bind_ip=ip,
        handler_dir=handler_dir,
        log_dir=log_dir,
        **daemon_kwargs,
    )
    daemon.start()
