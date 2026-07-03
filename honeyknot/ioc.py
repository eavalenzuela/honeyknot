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
    {"urls": [...], "ips": [...], "ipv6": [...], "onions": [...],
     "downloads": [...], "shell": [...]}
    or None if the buffer is too binary or empty. Empty categories are
    omitted from the returned dict.

Each list is deduplicated and capped.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib

# URLs — http/https scheme, reasonable domain chars, optional port + path.
_URL_RE = re.compile(
    rb"https?://[a-zA-Z0-9][a-zA-Z0-9\-.]{0,253}(?::\d{1,5})?(?:/[\w\-./?=&%+@#~:,;!$*]*)?",
    re.IGNORECASE,
)

# Tor hidden-service addresses (v2 = 16 chars, v3 = 56 chars, base32).
_ONION_RE = re.compile(
    rb"(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion\b",
    re.IGNORECASE,
)

# Dotted quad, with each octet in [0, 255].
_IPV4_RE = re.compile(
    rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"
)

# IPv6 literals. Deliberately conservative to avoid matching MAC addresses
# (six colon groups, no `::`) and HH:MM:SS timestamps: we only accept either
# the full 8-hextet form or a `::`-compressed form.
_IPV6_RE = re.compile(
    rb"(?<![0-9A-Fa-f:.])"
    rb"(?:"
    rb"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"           # full 8-group form
    rb"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4})?"  # xxxx:: / xxxx::yyyy
    rb"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"      # ::yyyy...
    rb")"
    rb"(?![0-9A-Fa-f:.])"
)

# Download commands — catch the command + its argument block up to a
# separator (;, |, &, CR, LF). busybox wrapper is surprisingly common on
# Mirai-class malware; the Windows LOLBINs (certutil / bitsadmin / mshta /
# regsvr32 / Invoke-WebRequest) are the equivalent on the PowerShell side.
_DOWNLOAD_RE = re.compile(
    rb"(?:wget|curl|tftp|fetch|scp|"
    rb"busybox\s+(?:wget|tftp|curl)|"
    rb"certutil(?:\.exe)?[^\r\n]*?-urlcache|"
    rb"bitsadmin(?:\.exe)?[^\r\n]*?/transfer|"
    rb"(?:iwr|invoke-webrequest|invoke-restmethod|irm|start-bitstransfer|wget|curl)\b|"
    rb"mshta(?:\.exe)?|regsvr32(?:\.exe)?[^\r\n]*?/i:https?)"
    rb"[ \t]?[^\r\n;|&\x00]{0,300}",
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
# Minimum size of a base64 run we'll try to decode. Below this it's just
# noise that happens to look base64-ish.
MIN_BASE64_RUN = 64
# Cap on decoded bytes per layer so an evil payload can't make us
# allocate arbitrary memory.
MAX_DECODED_BYTES = 2 * 1024 * 1024

_BASE64_RUN_RE = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_BASE64_RUN)


def extract_iocs(data: bytes) -> dict[str, list[str]] | None:
    """Return extracted indicators, or None if nothing worth reporting.

    Runs regexes over `data` directly (if it's text-like) and over any
    single layer of gzip/zlib/base64 decoding we can peel off. IOCs
    from decoded layers are merged with top-level hits and then
    deduplicated.
    """
    if len(data) < 8:
        return None

    urls: list[bytes] = []
    ips: list[bytes] = []
    ipv6: list[bytes] = []
    onions: list[bytes] = []
    downloads: list[bytes] = []
    shell: list[bytes] = []

    for layer in _decoded_layers(data):
        # Per-layer printable gate: skip mostly-binary layers entirely to
        # avoid hallucinating IPs/URLs out of random bytes. Decoded layers
        # from gzip/base64 re-qualify here on their own merits.
        if _printable_ratio(layer) < MIN_PRINTABLE_RATIO:
            continue
        urls.extend(_URL_RE.findall(layer))
        ips.extend(_IPV4_RE.findall(layer))
        ipv6.extend(_IPV6_RE.findall(layer))
        onions.extend(_ONION_RE.findall(layer))
        downloads.extend(_DOWNLOAD_RE.findall(layer))
        shell.extend(_SHELL_RE.findall(layer))

    result = {
        "urls": _dedup_cap(urls),
        "ips": _dedup_cap(ips, filter_noise=_noisy_ip),
        "ipv6": _dedup_cap(ipv6, filter_noise=_noisy_ipv6),
        "onions": _dedup_cap(onions, lower=True),
        "downloads": _dedup_cap(downloads),
        "shell": _dedup_cap(shell),
    }
    # Drop empty categories so events/sidecars stay compact.
    result = {k: v for k, v in result.items() if v}
    if not result:
        return None
    return result


def _decoded_layers(data: bytes):
    """Yield `data` and up to one decoded layer of gzip/zlib/base64.

    Gzip/zlib magic is searched for anywhere in the buffer, not just at
    position 0, because attacker payloads typically arrive inside HTTP
    or other protocol framing that pushes the magic past the head.
    """
    yield data

    # gzip magic \x1f\x8b\x08 (deflate is the only real compression method).
    # Scan for all offsets so we also catch gzip blobs embedded in HTTP
    # bodies, etc.
    gz_offsets: list[int] = []
    start = 0
    while True:
        idx = data.find(b"\x1f\x8b\x08", start)
        if idx == -1 or len(gz_offsets) >= 4:
            break
        gz_offsets.append(idx)
        start = idx + 3
    for idx in gz_offsets:
        try:
            decoded = gzip.decompress(data[idx:])
        except (OSError, EOFError, zlib.error):
            continue
        if decoded and len(decoded) <= MAX_DECODED_BYTES:
            yield decoded

    # raw zlib at position 0 only — too many false positives mid-stream
    if data[:1] == b"\x78":
        try:
            decoded = zlib.decompress(data)
            if decoded and len(decoded) <= MAX_DECODED_BYTES:
                yield decoded
        except zlib.error:
            pass

    # base64-looking runs embedded in text. We try each run independently;
    # typical case is a single long blob inside a webshell or powershell -enc.
    seen_decoded: set[bytes] = set()
    for match in _BASE64_RUN_RE.findall(data):
        if match in seen_decoded:
            continue
        seen_decoded.add(match)
        try:
            decoded = base64.b64decode(match, validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded and len(decoded) <= MAX_DECODED_BYTES:
            yield decoded


def _printable_ratio(data: bytes) -> float:
    # ASCII printable + whitespace we consider "text-like".
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(data) if data else 0.0


def _dedup_cap(matches, filter_noise=None, lower=False) -> list[str]:
    seen: list[str] = []
    for raw in matches:
        text = raw.decode("utf-8", errors="replace").rstrip(".,)\"'>")
        if lower:
            text = text.lower()
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


def _noisy_ipv6(addr: str) -> bool:
    # Drop loopback / unspecified / link-local-ish literals that aren't
    # interesting as C2 indicators.
    low = addr.lower()
    return low in ("::", "::1") or low.startswith(("fe80:", "ff02:"))
