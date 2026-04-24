"""Quick IOC extraction over captured byte streams.

The honeypot records a lot of payloads; ~90% of them are commodity botnet
probes that look the same modulo the C2 target and the dropper URL. Pulling
those indicators out at capture time means events.jsonl carries actionable
fields ("this session tried to fetch http://x.y.z/sh") without needing to
eyeball the raw bytes.

This is not a full static-analysis pass — no unpacking, no string decoding
of obfuscated scripts. It's regex over bytes, gated by a printable-ratio
check so we don't hallucinate "IPs" out of binary SMB/RDP frames.

Output shape:
    {"urls": [...], "ips": [...], "downloads": [...], "shell": [...]}
    or None if the buffer is too binary or empty.

Each list is deduplicated and capped.
"""

from __future__ import annotations

import re

# URLs — http/https scheme, reasonable domain chars, optional port + path.
_URL_RE = re.compile(
    rb"https?://[a-zA-Z0-9][a-zA-Z0-9\-.]{0,253}(?::\d{1,5})?(?:/[\w\-./?=&%+@#~:,;!$*]*)?",
    re.IGNORECASE,
)

# Dotted quad, with each octet in [0, 255].
_IPV4_RE = re.compile(
    rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"
)

# Download commands — catch the command + its argument block up to a
# separator (;, |, &, CR, LF). busybox wrapper is surprisingly common on
# Mirai-class malware.
_DOWNLOAD_RE = re.compile(
    rb"(?:wget|curl|tftp|fetch|busybox\s+(?:wget|tftp|curl))"
    rb"[ \t][^\r\n;|&\x00]{0,300}",
    re.IGNORECASE,
)

# Shell snippets attackers use when pivoting from a webshell / RCE.
_SHELL_RE = re.compile(
    rb"(?:chmod\s+\+?x|base64\s+-d|eval\s*\(|/tmp/[\w.\-]+|/dev/shm/[\w.\-]+|"
    rb"nc\s+-[lpev]+|/bin/sh\b|/bin/bash\b|python\s+-c|perl\s+-e|"
    rb"powershell\s+-[ecEC])"
    rb"[^\r\n\x00]{0,200}",
    re.IGNORECASE,
)

MAX_PER_KIND = 20
MIN_PRINTABLE_RATIO = 0.5


def extract_iocs(data: bytes) -> dict[str, list[str]] | None:
    """Return extracted indicators, or None if nothing worth reporting."""
    if len(data) < 8:
        return None
    if _printable_ratio(data) < MIN_PRINTABLE_RATIO:
        return None

    urls = _dedup_cap(_URL_RE.findall(data))
    ips = _dedup_cap(_IPV4_RE.findall(data), filter_noise=_noisy_ip)
    downloads = _dedup_cap(_DOWNLOAD_RE.findall(data))
    shell = _dedup_cap(_SHELL_RE.findall(data))

    if not (urls or ips or downloads or shell):
        return None

    return {
        "urls": urls,
        "ips": ips,
        "downloads": downloads,
        "shell": shell,
    }


def _printable_ratio(data: bytes) -> float:
    # ASCII printable + whitespace we consider "text-like".
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(data) if data else 0.0


def _dedup_cap(matches, filter_noise=None) -> list[str]:
    seen: list[str] = []
    for raw in matches:
        text = raw.decode("utf-8", errors="replace").rstrip(".,)\"'>")
        if filter_noise is not None and filter_noise(text):
            continue
        if text not in seen:
            seen.append(text)
        if len(seen) >= MAX_PER_KIND:
            break
    return seen


def _noisy_ip(ip: str) -> bool:
    # Drop internal/self-ish addresses that aren't interesting as IOCs.
    return ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255")
