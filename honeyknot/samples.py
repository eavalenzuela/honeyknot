"""Content-addressed sample store.

Every captured byte stream is hashed; the hash becomes the filename. If
two attackers drop the same payload from different IPs, only one file
lands on disk. The first byte of the hex digest is used as a shard so a
single directory never accumulates millions of files.

Callers get back `(sha256_hex, is_new)` so they can decide what to log.
A re-hit is interesting too (it's the same attacker tool hitting again),
just less noisy — we don't want to write 50k copies of the same 10KB
stager.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger("honeyknot.samples")


class SampleStore:
    def __init__(self, log_dir: str | Path, min_size: int = 1):
        self.root = Path(log_dir) / "samples"
        self.min_size = min_size
        self.root.mkdir(parents=True, exist_ok=True)

    def store(self, data: bytes) -> tuple[str, bool, Path | None]:
        """Hash `data`, write it if not already present.

        Returns `(sha256_hex, is_new, path)`. `path` is None if the data
        was too small to store (below `min_size`) — but we still return
        the hash so callers can use it as a correlation key.
        """
        digest = hashlib.sha256(data).hexdigest()
        if len(data) < self.min_size:
            return digest, False, None
        shard = self.root / digest[:2]
        shard.mkdir(exist_ok=True)
        path = shard / f"{digest}.bin"
        if path.exists():
            return digest, False, path
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError as e:
            logger.warning("sample write failed for %s: %s", digest, e)
            return digest, False, None
        return digest, True, path
