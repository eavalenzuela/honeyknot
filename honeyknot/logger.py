"""Centralized logging for honeyknot."""

import logging
import logging.handlers
import os
from pathlib import Path


def setup_logging(log_dir: str, verbose: bool = False) -> logging.Logger:
    """Configure the root honeyknot logger with a console handler.

    Returns the root 'honeyknot' logger.
    """
    root = logging.getLogger("honeyknot")
    root.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on repeated calls
    if not root.handlers:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG if verbose else logging.INFO)
        console.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        root.addHandler(console)

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)

    return root


def get_port_logger(port: int, log_dir: str) -> logging.Logger:
    """Get a per-port logger that writes to a rotating log file.

    Each port gets its own log file at <log_dir>/<port>.log with
    automatic rotation at 10MB and 5 backup files.
    """
    logger = logging.getLogger(f"honeyknot.port.{port}")

    # Avoid duplicate file handlers
    if not any(isinstance(h, logging.handlers.RotatingFileHandler)
               for h in logger.handlers):
        log_path = Path(log_dir) / f"{port}.log"
        fh = logging.handlers.RotatingFileHandler(
            str(log_path),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(message)s"
        ))
        logger.addHandler(fh)

    return logger
