"""Minimal TLS ClientHello parser for SNI extraction.

We don't terminate TLS anywhere that would need this — it's strictly for
fingerprinting attacker-side tooling. Given a bytes buffer that starts
with a TLS record (Content-Type 0x16 = handshake), return the
server_name extension value if any, or None.

Layout we walk:
    TLS record: type(1) version(2) length(2) → handshake_bytes
    Handshake: type=1(ClientHello)(1) length(3) version(2) random(32)
               session_id_len(1) session_id(var) cipher_suites_len(2)
               cipher_suites(var) compression_len(1) compression(var)
               extensions_len(2) extensions(var)
    SNI extension: type=0x0000, length(2), server_name_list_len(2),
                   name_type=0(1), hostname_len(2), hostname(var)
"""

from __future__ import annotations

import struct


def extract_sni(data: bytes) -> str | None:
    if len(data) < 5 or data[0] != 0x16:
        return None
    rec_len = struct.unpack(">H", data[3:5])[0]
    if 5 + rec_len > len(data):
        # truncated is ok — SNI is near the start of the handshake
        pass
    pos = 5
    if pos + 4 > len(data):
        return None
    if data[pos] != 0x01:  # ClientHello
        return None
    hs_len = int.from_bytes(data[pos + 1:pos + 4], "big")
    pos += 4
    end = min(pos + hs_len, len(data))
    if pos + 2 + 32 + 1 > end:
        return None
    pos += 2 + 32                        # version + random
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos + 2 > end:
        return None
    cs_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2 + cs_len
    if pos + 1 > end:
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos + 2 > end:
        return None
    ext_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    ext_end = min(pos + ext_len, end)

    while pos + 4 <= ext_end:
        etype, elen = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        if pos + elen > ext_end:
            return None
        if etype == 0x0000:              # server_name
            ext = data[pos:pos + elen]
            if len(ext) < 5:
                return None
            list_len = struct.unpack(">H", ext[:2])[0]
            if 2 + list_len > len(ext):
                return None
            name_type = ext[2]
            if name_type != 0:
                return None
            host_len = struct.unpack(">H", ext[3:5])[0]
            if 5 + host_len > len(ext):
                return None
            return ext[5:5 + host_len].decode("ascii", errors="replace")
        pos += elen
    return None
