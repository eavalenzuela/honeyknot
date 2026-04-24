"""Content-addressed sample store.

Every captured byte stream is hashed; the hash becomes the filename. If
two attackers drop the same payload from different IPs, only one file
lands on disk. The first byte of the hex digest is used as a shard so a
single directory never accumulates millions of files.

Callers get back `(sha256_hex, is_new)` so they can decide what to log.
A re-hit is interesting too (it's the same attacker tool hitting again),
just less noisy — we don't want to write 50k copies of the same 10KB
stager.

Alongside the sample file, we maintain a `<sha>.meta.json` sidecar with
aggregate info: first_seen / last_seen, hit_count, size, distinct peer
IPs (bounded), and a merged IOC set. Operators triaging a specific
sample can read the sidecar without replaying `events.jsonl`.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("honeyknot.samples")

MAX_PEERS_PER_SAMPLE = 50
MAX_IOCS_PER_KIND = 50


class SampleStore:
    def __init__(self, log_dir: str | Path, min_size: int = 1):
        self.root = Path(log_dir) / "samples"
        self.min_size = min_size
        self.root.mkdir(parents=True, exist_ok=True)
        self._meta_lock = threading.Lock()

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

    def update_meta(self, digest: str, *, size: int,
                    peer: tuple | None = None,
                    iocs: dict | None = None,
                    analyzer: dict | None = None,
                    yara: list | None = None) -> None:
        """Merge a new hit's metadata into `<sha>.meta.json`.

        Safe to call concurrently from the asyncio loop; a threading.Lock
        serializes disk access. Best-effort — a failure to write metadata
        never blocks capture.
        """
        if not digest:
            return
        shard = self.root / digest[:2]
        meta_path = shard / f"{digest}.meta.json"

        with self._meta_lock:
            meta = self._load_meta(meta_path)
            now = datetime.now(UTC).isoformat(timespec="seconds")
            if "first_seen" not in meta:
                meta["first_seen"] = now
                meta["size"] = size
                meta["hit_count"] = 0
                meta["peers"] = []
                meta["iocs"] = {"urls": [], "ips": [],
                                "downloads": [], "shell": []}
            meta["last_seen"] = now
            meta["hit_count"] = meta.get("hit_count", 0) + 1

            if peer is not None:
                peer_ip = peer[0] if isinstance(peer, tuple) and peer else str(peer)
                peers = meta.setdefault("peers", [])
                if peer_ip not in peers and len(peers) < MAX_PEERS_PER_SAMPLE:
                    peers.append(peer_ip)

            if iocs:
                acc = meta.setdefault("iocs", {})
                for kind in ("urls", "ips", "downloads", "shell"):
                    bucket = acc.setdefault(kind, [])
                    for item in iocs.get(kind, []):
                        if item not in bucket and len(bucket) < MAX_IOCS_PER_KIND:
                            bucket.append(item)

            if analyzer:
                meta["analyzer"] = analyzer

            if yara:
                existing = {m.get("rule") for m in meta.get("yara", [])}
                yara_bucket = meta.setdefault("yara", [])
                for m in yara:
                    if m.get("rule") not in existing:
                        yara_bucket.append(m)
                        existing.add(m.get("rule"))

            self._save_meta_atomic(meta_path, meta)

    def _load_meta(self, path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("meta load failed for %s: %s", path, e)
            return {}

    def _save_meta_atomic(self, path: Path, meta: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, sort_keys=False)
            os.replace(tmp, path)
        except OSError as e:
            logger.warning("meta write failed for %s: %s", path, e)
            with contextlib.suppress(OSError):
                tmp.unlink()
