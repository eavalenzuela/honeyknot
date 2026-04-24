"""Tests for the per-session PCAP-ng writer."""

import struct

from honeyknot.pcap import (
    BLOCK_EPB,
    BLOCK_IDB,
    BLOCK_SHB,
    BYTE_ORDER_MAGIC,
    PcapngWriter,
    _internet_checksum,
)


def _read_blocks(path):
    """Yield (block_type, body_bytes) tuples from a pcap-ng file."""
    data = path.read_bytes()
    pos = 0
    while pos < len(data):
        block_type, total = struct.unpack("<II", data[pos:pos + 8])
        body = data[pos + 8:pos + total - 4]
        tail = struct.unpack("<I", data[pos + total - 4:pos + total])[0]
        assert tail == total, "pcap-ng trailing length mismatch"
        yield block_type, body
        pos += total


class TestPcapng:
    def test_header_and_interface_written(self, tmp_path):
        path = tmp_path / "x.pcapng"
        w = PcapngWriter(path, ("10.0.0.5", 12345), "127.0.0.1", 22)
        w.close()
        blocks = list(_read_blocks(path))
        assert blocks[0][0] == BLOCK_SHB
        # First 4 bytes of SHB body are the byte-order magic
        assert struct.unpack("<I", blocks[0][1][:4])[0] == BYTE_ORDER_MAGIC
        assert blocks[1][0] == BLOCK_IDB

    def test_round_trip_packets(self, tmp_path):
        path = tmp_path / "x.pcapng"
        w = PcapngWriter(path, ("10.0.0.5", 12345), "127.0.0.1", 22)
        w.write_inbound(b"GET / HTTP/1.0\r\n\r\n")
        w.write_outbound(b"HTTP/1.0 200 OK\r\n\r\nhi")
        w.write_inbound(b"bye")
        w.close()

        blocks = list(_read_blocks(path))
        epbs = [b for b in blocks if b[0] == BLOCK_EPB]
        assert len(epbs) == 3

        # Each EPB body: interface_id(4) ts_h(4) ts_l(4) cap_len(4) orig_len(4) + pkt
        # Verify the first inbound packet has Ethernet IPv4 ethertype 0x0800
        first_pkt = epbs[0][1][20:20 + struct.unpack("<I", epbs[0][1][12:16])[0]]
        assert first_pkt[12:14] == b"\x08\x00"

    def test_tcp_seq_advances_per_direction(self, tmp_path):
        path = tmp_path / "x.pcapng"
        w = PcapngWriter(path, ("10.0.0.5", 12345), "127.0.0.1", 22)
        w.write_inbound(b"ABCDE")      # 5 bytes, client seq 1→6
        w.write_inbound(b"FGHI")       # 4 bytes, client seq 6→10
        w.write_outbound(b"XYZ")       # 3 bytes, server seq 1→4
        w.close()

        blocks = list(_read_blocks(path))
        epbs = [b for b in blocks if b[0] == BLOCK_EPB]

        def extract_tcp_seq(epb_body):
            # EPB header is 20 bytes; then Ethernet(14) + IPv4(20) + TCP, seq at TCP+4..+8
            eth_ip_tcp = epb_body[20:]
            seq = struct.unpack(">I", eth_ip_tcp[14 + 20 + 4:14 + 20 + 8])[0]
            return seq

        seqs = [extract_tcp_seq(b[1]) for b in epbs]
        assert seqs[0] == 1   # first inbound
        assert seqs[1] == 6   # second inbound, advanced by 5
        assert seqs[2] == 1   # first outbound, separate counter

    def test_close_is_idempotent(self, tmp_path):
        path = tmp_path / "x.pcapng"
        w = PcapngWriter(path, ("10.0.0.5", 12345), "127.0.0.1", 22)
        w.close()
        w.close()  # should not raise

    def test_writes_after_close_no_op(self, tmp_path):
        path = tmp_path / "x.pcapng"
        w = PcapngWriter(path, ("10.0.0.5", 12345), "127.0.0.1", 22)
        w.close()
        w.write_inbound(b"should be ignored")  # must not raise


class TestChecksum:
    def test_rfc1071_example(self):
        # Classic example from RFC 1071 appendix.
        data = bytes.fromhex("0001f203f4f5f6f7")
        cksum = _internet_checksum(data)
        # Sum of the 16-bit words with carry folded: 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7
        # = 0x2ddf0; folded: 0xddf2; one's complement: 0x220d
        assert cksum == 0x220D

    def test_odd_length_padded(self):
        # Just needs to not raise and produce a 16-bit value
        c = _internet_checksum(b"\x00\x01\x02")
        assert 0 <= c <= 0xFFFF
