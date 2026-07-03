"""Offline triage over events.jsonl — top peers/samples/IOCs at a glance.

`honeyknot-stats` reads the JSONL event log (and its rotated backups) and
prints a compact summary so an operator can triage a capture run without
hand-rolling `jq` pipelines:

    honeyknot-stats -ld logs/            # summarize logs/events.jsonl(+backups)
    honeyknot-stats --events-file a.jsonl -n 20

Everything is derived from the event stream, so it works against archived
logs too — no live daemon required.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

IOC_KINDS = ("urls", "ips", "ipv6", "onions", "downloads", "shell")


def iter_event_files(log_dir: Path) -> Iterator[Path]:
    """Yield `events.jsonl` and any rotated `events.jsonl.N` backups."""
    base = log_dir / "events.jsonl"
    if base.exists():
        yield base
    backups = sorted(
        log_dir.glob("events.jsonl.*"),
        key=lambda p: int(p.suffix[1:]) if p.suffix[1:].isdigit() else 0,
    )
    yield from backups


def load_events(files: Iterable[Path]) -> Iterator[dict]:
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue


def build_report(events: Iterable[dict], top: int = 10) -> str:
    total = 0
    by_event: Counter = Counter()
    by_protocol: Counter = Counter()
    peers: Counter = Counter()
    samples: Counter = Counter()
    iocs: dict[str, Counter] = {k: Counter() for k in IOC_KINDS}

    for e in events:
        total += 1
        by_event[e.get("event", "?")] += 1
        by_protocol[e.get("protocol", "?")] += 1
        peer = e.get("peer")
        if peer:
            peers[peer] += 1
        sha = e.get("sha256")
        if sha:
            samples[sha] += 1
        if e.get("event") == "ioc":
            for kind in IOC_KINDS:
                for item in e.get(kind, []) or []:
                    iocs[kind][item] += 1

    lines: list[str] = []
    lines.append(f"Total events:    {total}")
    lines.append(f"Unique peers:    {len(peers)}")
    lines.append(f"Unique samples:  {len(samples)}")

    def section(title: str, counter: Counter, limit: int | None = None) -> None:
        rows = counter.most_common(limit)
        if not rows:
            return
        lines.append("")
        lines.append(f"== {title} ==")
        for name, n in rows:
            lines.append(f"  {n:>8}  {name}")

    section("Events by kind", by_event)
    section("Events by protocol", by_protocol)
    section(f"Top {top} source peers", peers, top)
    section(f"Top {top} samples (sha256)", samples, top)
    for kind in IOC_KINDS:
        section(f"Top {top} {kind}", iocs[kind], top)

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="honeyknot-stats",
        description="Summarize a honeyknot events.jsonl log for triage.",
    )
    parser.add_argument(
        "-ld", "--log-dir", default="logs/",
        help="log directory containing events.jsonl (default: logs/)",
    )
    parser.add_argument(
        "--events-file", default=None,
        help="explicit path to an events.jsonl file (overrides --log-dir)",
    )
    parser.add_argument(
        "-n", "--top", type=int, default=10,
        help="rows to show per top-N section (default: 10)",
    )
    args = parser.parse_args(argv)

    if args.events_file:
        files = [Path(args.events_file)]
    else:
        files = list(iter_event_files(Path(args.log_dir)))

    if not files or not any(p.exists() for p in files):
        target = args.events_file or args.log_dir
        print(f"No events found (looked in {target})", file=sys.stderr)
        return 1

    print(build_report(load_events(files), top=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
