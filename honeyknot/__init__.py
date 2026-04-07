"""Honeyknot: A highly-configurable multi-port honeypot for farming malware."""

__version__ = "0.3.0"


def run_from_interactive_shell(ip, handler_dir="handlers/", log_dir="logs/",
                               thread_count=5, verbose=False):
    """Start honeyknot from a Python interactive shell.

    Args:
        ip: IP address to bind sockets to.
        handler_dir: Path to directory containing TOML handler definitions.
        log_dir: Path to directory for log output.
        thread_count: Number of threads per port process.
        verbose: Enable debug-level logging.
    """
    from honeyknot.logger import setup_logging
    from honeyknot.server import HoneyknotDaemon

    setup_logging(log_dir, verbose=verbose)
    daemon = HoneyknotDaemon(
        bind_ip=ip,
        handler_dir=handler_dir,
        log_dir=log_dir,
        thread_count=thread_count,
    )
    daemon.start()
