"""LDAP honeypot on TCP/389 — capture bind credentials and search bases.

LDAP is heavily brute-forced (Active Directory, OpenLDAP, appliance admin
accounts). We implement just enough BER to parse a `bindRequest` — pulling
out the bind DN and the simple (cleartext) password — and a `searchRequest`
baseObject, then answer with a `success` result so the client keeps going.

LDAP wire framing is BER-encoded (RFC 4511):
    LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE ... }
Tags we care about:
    0x30 SEQUENCE   0x02 INTEGER   0x04 OCTET STRING   0x0A ENUMERATED
    0x60 bindRequest [APP 0]        0x61 bindResponse [APP 1]
    0x63 searchRequest [APP 3]      0x65 searchResDone [APP 5]
    0x42 unbindRequest [APP 2]      0x80 simple-auth [context 0]
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.ldap")

TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_BIND_REQUEST = 0x60
TAG_BIND_RESPONSE = 0x61
TAG_SEARCH_REQUEST = 0x63
TAG_SEARCH_DONE = 0x65
TAG_UNBIND_REQUEST = 0x42
TAG_SIMPLE_AUTH = 0x80
TAG_SASL_AUTH = 0xA3

MAX_MESSAGE = 1 << 20  # 1 MiB cap on a single LDAP message


class LDAPHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)
        while buf and not ctx.closed:
            if buf[0] != TAG_SEQUENCE:
                ctx.close()
                return
            parsed = _read_tlv(buf, 0)
            if parsed is None:
                return  # need more bytes (or an over-long length — idle-reaped)
            _tag, value, end = parsed
            if end > MAX_MESSAGE:
                ctx.close()
                return
            del buf[:end]
            await self._handle_message(value, ctx)

    async def _handle_message(self, value: bytes, ctx: ConnectionContext) -> None:
        mid = _read_tlv(value, 0)
        if mid is None or mid[0] != TAG_INTEGER:
            return
        message_id = int.from_bytes(mid[1], "big") if mid[1] else 0
        op = _read_tlv(value, mid[2])
        if op is None:
            return
        op_tag, op_value, _ = op

        if op_tag == TAG_BIND_REQUEST:
            await self._bind(message_id, op_value, ctx)
        elif op_tag == TAG_SEARCH_REQUEST:
            await self._search(message_id, op_value, ctx)
        elif op_tag == TAG_UNBIND_REQUEST:
            ctx.close()

    async def _bind(self, message_id: int, op_value: bytes,
                    ctx: ConnectionContext) -> None:
        # bindRequest ::= { version INTEGER, name LDAPDN, authentication }
        version = _read_tlv(op_value, 0)
        if version is None:
            return
        name = _read_tlv(op_value, version[2])
        bind_dn = ""
        pos = version[2]
        if name is not None and name[0] == TAG_OCTET_STRING:
            bind_dn = name[1].decode("utf-8", errors="replace")
            pos = name[2]
        auth = _read_tlv(op_value, pos)
        method = "unknown"
        password = ""
        if auth is not None:
            if auth[0] == TAG_SIMPLE_AUTH:
                method = "simple"
                password = auth[1].decode("utf-8", errors="replace")
            elif auth[0] == TAG_SASL_AUTH:
                method = "sasl"

        logger.info("LDAP bind from %s: dn=%r method=%s", ctx.addr,
                    bind_dn, method)
        ctx.event("credentials", service="ldap", username=bind_dn,
                  password=password, method=method)
        await ctx.send(_ldap_result(message_id, TAG_BIND_RESPONSE))

    async def _search(self, message_id: int, op_value: bytes,
                      ctx: ConnectionContext) -> None:
        base = _read_tlv(op_value, 0)
        base_dn = ""
        if base is not None and base[0] == TAG_OCTET_STRING:
            base_dn = base[1].decode("utf-8", errors="replace")
        logger.info("LDAP search from %s: base=%r", ctx.addr, base_dn)
        ctx.event("ldap_search", base=base_dn)
        # Return no entries, just a success searchResultDone.
        await ctx.send(_ldap_result(message_id, TAG_SEARCH_DONE))


def _read_tlv(buf, pos: int):
    """Decode one BER TLV at `pos`.

    Returns `(tag, value_bytes, next_pos)`, or None if the buffer is too
    short to hold the element or the length encoding is unsupported.
    """
    if pos + 2 > len(buf):
        return None
    tag = buf[pos]
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        num = first & 0x7F
        if num == 0 or num > 4 or pos + num > len(buf):
            return None
        length = int.from_bytes(buf[pos:pos + num], "big")
        pos += num
    if pos + length > len(buf):
        return None
    return tag, bytes(buf[pos:pos + length]), pos + length


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _int_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    # +1 padding byte guarantees the high bit stays clear (positive integer).
    return n.to_bytes((n.bit_length() + 8) // 8, "big")


def _ldap_result(message_id: int, op_tag: int, result_code: int = 0) -> bytes:
    """Build an LDAPMessage wrapping a success LDAPResult of type `op_tag`."""
    result = (
        bytes([0x0A, 0x01, result_code])   # resultCode ENUMERATED
        + b"\x04\x00"                       # matchedDN ""
        + b"\x04\x00"                       # diagnosticMessage ""
    )
    protocol_op = _tlv(op_tag, result)
    msgid = _tlv(TAG_INTEGER, _int_bytes(message_id))
    return _tlv(TAG_SEQUENCE, msgid + protocol_op)
