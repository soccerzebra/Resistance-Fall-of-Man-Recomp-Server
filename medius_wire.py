#!/usr/bin/env python3
"""The Medius wire format, in one place.

Both directions on the multiplayer sockets are the same shape -- a type byte
and a little-endian length, then a payload that may itself contain a
little-endian length:

    u8      type
    u16 LE  msg_len      length of everything after these 3 bytes
    u8[..]  payload      msg_len bytes

The SCERT certificate record on :10071 is that, with a second length inside
the payload (read back with tools/mp/make_reply.py):

    type 0x24 | msg_len (LE) | fields[12] | der_len (LE) | DER | 00 00 00 00

so a 707-byte DER gives msg_len 725 (12 + 2 + 707 + 4) and 3 + 725 = 728 bytes
on the wire, which is what the client sends and what logs/mp/medius.log shows.

The old code in this directory labelled the first three bytes as part of a
"15-byte header" and hard-coded the outer length, so any certificate other
than the client's own was emitted with a length that did not match the record
(it said 725 while carrying 737). That is a framing error the client rejects
before it ever looks at the certificate. Hence this module: one encoder, one
decoder, both lengths always derived.
"""
from __future__ import annotations

TYPE_CERT = 0x24           # certificate record (client's first send on :10071)
TYPE_ABORT = 0x20          # the 4-byte give-up: 20 01 00 01

TRAILER = b"\x00\x00\x00\x00"
SCERT_FIELDS = bytes.fromhex("010070000300000600040100")   # 12 bytes, client's own

HEADER = 3                 # type + u16 LE length


def encode(typ: int, payload: bytes) -> bytes:
    """One message: type byte, u16 LE length of the payload, payload."""
    if not 0 <= typ <= 0xFF:
        raise ValueError("type must fit in one byte")
    if len(payload) > 0xFFFF:
        raise ValueError("payload does not fit a u16 length")
    return bytes([typ]) + len(payload).to_bytes(2, "little") + payload


def decode_prefix(buf: bytes) -> dict | None:
    """Header of the first message in buf, or None if it is not all there yet.

    -> {"type", "msg_len", "total", "payload", "complete"}
    """
    if len(buf) < HEADER:
        return None
    msg_len = buf[1] | (buf[2] << 8)
    total = HEADER + msg_len
    return {"type": buf[0], "msg_len": msg_len, "total": total,
            "payload": buf[HEADER:total], "complete": len(buf) >= total}


def encode_scert(der: bytes, fields: bytes = SCERT_FIELDS,
                 typ: int = TYPE_CERT, trailer: bytes = TRAILER) -> bytes:
    """The certificate record: type, msg_len, fields, der_len, DER, trailer."""
    if len(fields) != 12:
        raise ValueError("the SCERT record fields are 12 bytes")
    payload = (fields + len(der).to_bytes(2, "little") + der + trailer)
    return encode(typ, payload)


def decode_scert(buf: bytes) -> dict | None:
    """Take apart a certificate record; None if the header is not all there."""
    hdr = decode_prefix(buf)
    if hdr is None:
        return None
    p = hdr["payload"]
    out = dict(hdr)
    out["fields"] = p[:12]
    if len(p) >= 14:
        der_len = p[12] | (p[13] << 8)
        out["der_len"] = der_len
        out["der"] = p[14:14 + der_len]
        out["trailer"] = p[14 + der_len:]
        out["consistent"] = (len(p) == 12 + 2 + der_len + len(out["trailer"]))
    else:
        out["der_len"] = None
        out["der"] = b""
        out["trailer"] = b""
        out["consistent"] = False
    return out


def describe(buf: bytes, tag: str = "") -> list[str]:
    """Human-readable lines for a record, for the server log."""
    hdr = decode_scert(buf)
    if hdr is None:
        return [f"{tag}short record ({len(buf)} bytes)"]
    lines = [f"{tag}type 0x{hdr['type']:02X}  msg_len {hdr['msg_len']} "
             f"(0x{hdr['msg_len']:04X})  fields {hdr['fields'].hex(' ')}  "
             f"der_len {hdr['der_len']}"]
    if len(buf) != hdr["total"]:
        lines.append(f"{tag}!! {len(buf)} bytes on the wire but type/msg_len say "
                     f"{hdr['total']}")
    if not hdr["consistent"]:
        lines.append(f"{tag}!! fields/der_len/trailer do not add up to msg_len "
                     f"({len(hdr['payload'])} payload bytes)")
    if hdr["der"][:1] == b"\x30":
        lines.append(f"{tag}body looks like DER (0x30 0x{hdr['der'][1]:02X}); "
                     f"{len(hdr['der'])} bytes")
    if hdr["trailer"]:
        lines.append(f"{tag}tail after DER = {hdr['trailer'].hex(' ')}")
    return lines


def _selftest() -> int:
    """The client's own record is 728 bytes; re-encoding must reproduce it."""
    der = bytes([0x30, 0x82]) + bytes(705)          # stand-in for the 707-byte DER
    client = encode_scert(der)
    assert len(client) == 728, len(client)
    assert client[:3] == bytes.fromhex("24d502"), client[:3].hex()
    back = decode_scert(client)
    assert back["der"] == der and back["consistent"] and back["complete"]
    assert back["fields"] == SCERT_FIELDS
    # a bigger DER must move BOTH lengths: this is the bug the old code had
    big = encode_scert(der + bytes(12))
    assert len(big) == 740, len(big)
    assert decode_scert(big)["msg_len"] == 737, decode_scert(big)["msg_len"]
    # and the abort the client gives up with
    abort = encode(TYPE_ABORT, b"\x01")
    assert abort == bytes.fromhex("20010001"), abort.hex()
    print("medius_wire selftest OK: 728-byte client record, 740-byte bigger "
          "record, 4-byte abort")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
