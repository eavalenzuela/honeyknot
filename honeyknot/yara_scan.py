"""Optional YARA scanning of captured samples.

yara-python is an optional runtime dependency. If it's not installed, we
log once at startup and run as a clean no-op. Rules are compiled once at
daemon start; scans run synchronously against the full captured buffer
on close / per datagram — for the payload sizes a honeypot sees (tens of
KB to a few MB), this is fast enough not to warrant a worker pool.

Match format (one per rule that fires):
    {"rule": str, "tags": list[str], "meta": dict, "strings": int}

`strings` is the count of matched string occurrences; the raw offsets are
not included to keep events.jsonl rows small. Operators wanting full
details should re-scan the sample file directly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover — exercised only when yara is absent
    yara = None

logger = logging.getLogger("honeyknot.yara_scan")


class YaraScanner:
    def __init__(self, rules_path: str | Path | None):
        self.rules = None
        self.path = Path(rules_path) if rules_path else None
        if self.path is None:
            return
        if yara is None:
            logger.warning("--yara-rules set but yara-python is not installed; "
                           "skipping YARA scanning")
            return
        if not self.path.exists():
            logger.error("YARA rules path does not exist: %s", self.path)
            return
        self.rules = self._compile(self.path)

    @property
    def enabled(self) -> bool:
        return self.rules is not None

    def _compile(self, path: Path):
        """Compile either a single .yar file or a directory of them."""
        try:
            if path.is_dir():
                files = {}
                for f in sorted(path.glob("*.yar")):
                    files[f.stem] = str(f)
                for f in sorted(path.glob("*.yara")):
                    files[f.stem] = str(f)
                if not files:
                    logger.error("No .yar/.yara files found in %s", path)
                    return None
                rules = yara.compile(filepaths=files)
                logger.info("Compiled %d YARA rule file(s) from %s",
                            len(files), path)
                return rules
            rules = yara.compile(filepath=str(path))
            logger.info("Compiled YARA rules from %s", path)
            return rules
        except yara.SyntaxError as e:
            logger.error("YARA compile error: %s", e)
            return None
        except OSError as e:
            logger.error("YARA I/O error: %s", e)
            return None

    def scan(self, data: bytes) -> list[dict[str, Any]]:
        """Return match records, or [] if no rules or no hits."""
        if not self.enabled or not data:
            return []
        try:
            matches = self.rules.match(data=data, timeout=10)
        except yara.Error as e:
            logger.warning("YARA scan failed: %s", e)
            return []
        return [
            {
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta),
                "strings": len(m.strings),
            }
            for m in matches
        ]
