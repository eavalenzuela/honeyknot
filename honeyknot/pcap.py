"""PCAP-ng per-session writer with synthesized IPv4+TCP framing.

The goal is to make every captured session ingestible by the standard
malware toolchain (Wireshark stream reassembly, Zeek, Suricata, etc.)
without running an actual packet sniffer.

We don't observe real packet timing or segmentation — honeyknot sits
above the socket, not on the wire. So we synthesize:

  - Stable fake MAC addresses (02:00:00:00:00:01 for the honeypot side,
    derived from the peer IP for the client side)
  - Ethernet + IPv4 + TCP headers with correct checksums
  - Monotonic TCP sequence numbers per direction, advancing by payload length
  - One PCAP-ng Enhanced Packet Block per observed chunk, with a real
    timestamp (microsecond resolution)

Link-layer is LINKTYPE_ETHERNET (1) so Wireshark picks up TCP by default.
No SYN/FIN handshake is emitted — we just start mid-stream with sequence
numbers beginning at 1. That's fine for Wireshark's "Follow TCP Stream"
view, which is the main intended consumer.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import struct
import time
from pathlib import Path

logger = logging.getLogger("honeyknot.pcap")

LINKTYPE_ETHERNET = 1
BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D


class PcapngWriter:
    """One pcap-ng file per session. Call `write_inbound` / `write_outbound`
    for each chunk in observed order, then `close`.

    `bind_ip` is what the honeypot listens on; used as the "server" side
    of the synthesized IPv4 header. Port numbers come from the actual
    peer and listening port so reassembly is unambiguous.
    """

    def __init__(self, path: Path, peer: tuple, bind_ip: str,
                 listen_port: int):
        self.path = path
        try:
            self._fp = open(path, "wb")  # noqa: SIM115  — long-lived
        except OSError as e:
            logger.warning("pcap open failed %s: %s", path, e)
            self._fp = None
            return

        # Parse IPs
        peer_ip_s = peer[0] if peer else "0.0.0.0"
        peer_port = peer[1] if peer and len(peer) > 1 else 0
        try:
            self._client_ip = ipaddress.IPv4Address(peer_ip_s).packed
        except (ValueError, ipaddress.AddressValueError):
            self._client_ip = b"\x00" * 4
        try:
            self._server_ip = ipaddress.IPv4Address(bind_ip).packed
        except (ValueError, ipaddress.AddressValueError):
            self._server_ip = b"\x00" * 4

        self._client_port = peer_port & 0xFFFF
        self._server_port = listen_port & 0xFFFF

        # MACs: stable, synthetic
        self._client_mac = b"\x02\x00" + self._client_ip
        self._server_mac = b"\x02\x00\x00\x00\x00\x01"

        # TCP sequence numbers, one per direction. Start at 1 in each.
        self._client_seq = 1
        self._server_seq = 1

        self._write_shb()
        self._write_idb()

    @property
    def open(self) -> bool:
        return self._fp is not None

    def write_inbound(self, data: bytes) -> None:
        """Client → server payload (what the attacker sent)."""
        if not self._fp or not data:
            return
        pkt = self._build_packet(
            src_mac=self._client_mac, dst_mac=self._server_mac,
            src_ip=self._client_ip, dst_ip=self._server_ip,
            src_port=self._client_port, dst_port=self._server_port,
            seq=self._client_seq, ack=self._server_seq,
            payload=data,
        )
        self._client_seq = (self._client_seq + len(data)) & 0xFFFFFFFF
        self._write_epb(pkt)

    def write_outbound(self, data: bytes) -> None:
        """Server → client payload (what the honeypot replied)."""
        if not self._fp or not data:
            return
        pkt = self._build_packet(
            src_mac=self._server_mac, dst_mac=self._client_mac,
            src_ip=self._server_ip, dst_ip=self._client_ip,
            src_port=self._server_port, dst_port=self._client_port,
            seq=self._server_seq, ack=self._client_seq,
            payload=data,
        )
        self._server_seq = (self._server_seq + len(data)) & 0xFFFFFFFF
        self._write_epb(pkt)

    def close(self) -> None:
        if self._fp is None:
            return
        with contextlib.suppress(OSError):
            self._fp.close()
        self._fp = None

    # --- PCAP-ng block serialization ----------------------------------

    def _write_shb(self) -> None:
        body = struct.pack("<IHHq",
                           BYTE_ORDER_MAGIC, 1, 0,  # major=1, minor=0
                           -1)                      # section length: unspecified
        self._write_block(BLOCK_SHB, body)

    def _write_idb(self) -> None:
        # LinkType (u16) + Reserved (u16) + SnapLen (u32)
        body = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 65535)
        self._write_block(BLOCK_IDB, body)

    def _write_epb(self, pkt: bytes) -> None:
        now = time.time_ns() // 1000  # microseconds
        ts_high = (now >> 32) & 0xFFFFFFFF
        ts_low = now & 0xFFFFFFFF
        cap_len = len(pkt)
        body = struct.pack("<IIIII",
                           0,           # interface id
                           ts_high, ts_low,
                           cap_len,     # captured length
                           cap_len)     # original length
        body += pkt
        # Pad to 32-bit boundary
        pad = (-cap_len) & 3
        if pad:
            body += b"\x00" * pad
        self._write_block(BLOCK_EPB, body)

    def _write_block(self, block_type: int, body: bytes) -> None:
        total = 12 + len(body)  # type(4) + len(4) + body + len(4)
        try:
            self._fp.write(struct.pack("<II", block_type, total))
            self._fp.write(body)
            self._fp.write(struct.pack("<I", total))
        except OSError as e:
            logger.warning("pcap write failed: %s", e)
            self._fp = None

    # --- Ethernet + IPv4 + TCP ----------------------------------------

    @staticmethod
    def _build_packet(*, src_mac: bytes, dst_mac: bytes,
                      src_ip: bytes, dst_ip: bytes,
                      src_port: int, dst_port: int,
                      seq: int, ack: int,
                      payload: bytes) -> bytes:
        eth = dst_mac + src_mac + b"\x08\x00"  # IPv4 ethertype

        tcp_header_len = 20
        tcp = struct.pack(
            ">HHIIBBHHH",
            src_port, dst_port,
            seq, ack,
            (tcp_header_len // 4) << 4,  # data offset
            0x18,                        # PSH | ACK
            65535,                       # window
            0,                           # checksum placeholder
            0,                           # urgent pointer
        )
        total_tcp = tcp + payload

        ip_total_len = 20 + len(total_tcp)
        ip_header_no_cksum = struct.pack(
            ">BBHHHBBH",
            0x45,                        # version=4, IHL=5
            0,                           # DSCP/ECN
            ip_total_len,
            0, 0x4000,                   # id, flags=DF
            64, 6,                       # TTL, proto=TCP
            0,                           # checksum placeholder
        ) + src_ip + dst_ip
        ip_checksum = _internet_checksum(ip_header_no_cksum)
        ip_header = (ip_header_no_cksum[:10]
                     + struct.pack(">H", ip_checksum)
                     + ip_header_no_cksum[12:])

        # TCP checksum with pseudo-header
        pseudo = src_ip + dst_ip + b"\x00\x06" + struct.pack(">H", len(total_tcp))
        tcp_checksum = _internet_checksum(pseudo + total_tcp)
        tcp_with_cksum = (total_tcp[:16]
                          + struct.pack(">H", tcp_checksum)
                          + total_tcp[18:])

        return eth + ip_header + tcp_with_cksum


def _internet_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum, returned as a 16-bit value."""
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


