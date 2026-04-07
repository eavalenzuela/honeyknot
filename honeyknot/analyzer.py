"""File type analysis for captured payloads.

Identifies file types by magic bytes in incoming request bodies
and returns a summary string for logging.
"""

import struct

# Magic byte signatures: (magic_bytes, file_type_name)
SIGNATURES = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
    (b"%PDF", "PDF"),
    (b"\xd0\xcf\x11\xe0", "OLE (DOC/XLS/PPT)"),
    (b"PK", "ZIP/OOXML (DOCX/XLSX/PPTX)"),
    (b"\x89PNG", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"Rar!", "RAR"),
    (b"\x1f\x8b", "GZIP"),
]


def identify_file_type(data: bytes) -> str | None:
    """Identify file type from magic bytes. Returns type name or None."""
    for magic, name in SIGNATURES:
        if data.startswith(magic):
            return name
    return None


def analyze_elf(header: bytes) -> dict:
    """Extract basic ELF header information."""
    info = {"type": "ELF"}
    if len(header) < 20:
        return info

    # ELF class: 32-bit or 64-bit
    ei_class = header[4]
    info["class"] = "ELF64" if ei_class == 2 else "ELF32"

    # Endianness
    ei_data = header[5]
    info["endian"] = "big" if ei_data == 2 else "little"

    # ELF type (at offset 16, 2 bytes)
    if len(header) >= 18:
        fmt = ">H" if ei_data == 2 else "<H"
        e_type = struct.unpack(fmt, header[16:18])[0]
        type_map = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
        info["elf_type"] = type_map.get(e_type, f"unknown({e_type})")

    return info


def analyze_pe(header: bytes) -> dict:
    """Extract basic PE/EXE header information."""
    info = {"type": "PE/EXE"}
    if len(header) < 64:
        return info

    # PE header offset is at 0x3C (4 bytes, little-endian)
    pe_offset = struct.unpack("<I", header[60:64])[0]
    if len(header) > pe_offset + 6:
        # Check for PE signature
        if header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            info["valid_pe"] = True
            # Machine type at PE+4
            machine = struct.unpack("<H", header[pe_offset + 4:pe_offset + 6])[0]
            machine_map = {0x14c: "x86", 0x8664: "x86_64", 0xaa64: "ARM64"}
            info["machine"] = machine_map.get(machine, f"0x{machine:04x}")
        else:
            info["valid_pe"] = False

    return info


def analyze_pdf(header: bytes) -> dict:
    """Extract basic PDF version information."""
    info = {"type": "PDF"}
    # PDF version is in the first line: %PDF-X.Y
    try:
        end = header.find(b"\n")
        if end == -1:
            end = min(len(header), 20)
        version_line = header[:end].decode("ascii", errors="replace")
        if version_line.startswith("%PDF-"):
            info["version"] = version_line[5:].strip()
    except Exception:
        pass
    return info


def analyze_payload(data: bytes) -> dict | None:
    """Analyze a payload and return file type info, or None if unrecognized.

    This is the main entry point used by the handler to analyze
    captured request bodies.
    """
    if len(data) < 4:
        return None

    file_type = identify_file_type(data)
    if file_type is None:
        return None

    header = data[:512]  # Read up to 512 bytes for analysis

    if data.startswith(b"\x7fELF"):
        return analyze_elf(header)
    elif data.startswith(b"MZ"):
        return analyze_pe(header)
    elif data.startswith(b"%PDF"):
        return analyze_pdf(header)
    else:
        # For other recognized types, return the basic identification
        return {"type": file_type}
