"""Tests for honeyknot.analyzer — file type detection and analysis."""

from honeyknot.analyzer import (
    analyze_elf,
    analyze_payload,
    analyze_pdf,
    analyze_pe,
    identify_file_type,
)


class TestIdentifyFileType:
    def test_elf(self):
        assert identify_file_type(b"\x7fELF" + b"\x00" * 60) == "ELF"

    def test_pe(self):
        assert identify_file_type(b"MZ" + b"\x00" * 62) == "PE/EXE"

    def test_pdf(self):
        assert identify_file_type(b"%PDF-1.7\n") == "PDF"

    def test_ole(self):
        assert identify_file_type(b"\xd0\xcf\x11\xe0" + b"\x00" * 60) == "OLE (DOC/XLS/PPT)"

    def test_zip(self):
        assert identify_file_type(b"PK\x03\x04" + b"\x00" * 60) == "ZIP/OOXML (DOCX/XLSX/PPTX)"

    def test_png(self):
        assert identify_file_type(b"\x89PNG" + b"\x00" * 60) == "PNG"

    def test_jpeg(self):
        assert identify_file_type(b"\xff\xd8\xff\xe0" + b"\x00" * 60) == "JPEG"

    def test_gif(self):
        assert identify_file_type(b"GIF89a" + b"\x00" * 58) == "GIF"

    def test_gzip(self):
        assert identify_file_type(b"\x1f\x8b\x08" + b"\x00" * 61) == "GZIP"

    def test_rar(self):
        assert identify_file_type(b"Rar!\x1a\x07" + b"\x00" * 58) == "RAR"

    def test_unknown(self):
        assert identify_file_type(b"hello world blah blah") is None

    def test_too_short(self):
        assert identify_file_type(b"hi") is None


class TestAnalyzeElf:
    def test_64bit_executable(self):
        # ELF magic + class=2(64bit) + data=1(LE) + padding + type=2(exec)
        header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x00" * 44
        result = analyze_elf(header)
        assert result["class"] == "ELF64"
        assert result["endian"] == "little"
        assert result["elf_type"] == "executable"

    def test_32bit_shared(self):
        header = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"\x03\x00" + b"\x00" * 44
        result = analyze_elf(header)
        assert result["class"] == "ELF32"
        assert result["elf_type"] == "shared"

    def test_big_endian(self):
        header = b"\x7fELF\x02\x02\x01\x00" + b"\x00" * 8 + b"\x00\x02" + b"\x00" * 44
        result = analyze_elf(header)
        assert result["endian"] == "big"
        assert result["elf_type"] == "executable"

    def test_short_header(self):
        result = analyze_elf(b"\x7fELF")
        assert result["type"] == "ELF"
        assert "class" not in result


class TestAnalyzePe:
    def test_valid_pe(self):
        # MZ header with PE offset at byte 60, then PE signature at that offset
        header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"  # PE offset = 0x40 = 64
        header += b"PE\x00\x00"  # PE signature at offset 64
        header += b"\x64\x86"  # machine = x86_64
        header += b"\x00" * 50
        result = analyze_pe(header)
        assert result["valid_pe"] is True
        assert result["machine"] == "x86_64"

    def test_short_header(self):
        result = analyze_pe(b"MZ" + b"\x00" * 10)
        assert result["type"] == "PE/EXE"


class TestAnalyzePdf:
    def test_version_extraction(self):
        result = analyze_pdf(b"%PDF-1.7\nsome content")
        assert result["version"] == "1.7"

    def test_version_2(self):
        result = analyze_pdf(b"%PDF-2.0\nmore stuff")
        assert result["version"] == "2.0"


class TestAnalyzePayload:
    def test_returns_none_for_unknown(self):
        assert analyze_payload(b"just some text data here") is None

    def test_returns_none_for_short_data(self):
        assert analyze_payload(b"hi") is None

    def test_elf_analysis(self):
        data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x00" * 44
        result = analyze_payload(data)
        assert result is not None
        assert result["type"] == "ELF"
        assert result["class"] == "ELF64"

    def test_pdf_analysis(self):
        result = analyze_payload(b"%PDF-1.5\ncontent here")
        assert result is not None
        assert result["type"] == "PDF"
        assert result["version"] == "1.5"

    def test_png_basic_identification(self):
        result = analyze_payload(b"\x89PNG\r\n\x1a\n" + b"\x00" * 56)
        assert result is not None
        assert result["type"] == "PNG"

    def test_gzip_basic_identification(self):
        result = analyze_payload(b"\x1f\x8b\x08\x00" + b"\x00" * 60)
        assert result is not None
        assert result["type"] == "GZIP"
