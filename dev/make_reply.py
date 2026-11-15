#!/usr/bin/env python3
"""Multiplayer: build logs/mp/reply.bin -- the server's SCERT answer.

The record the client sends on :10071, and the one we send back, are both Medius
messages -- one length-prefixed message with a second length-prefixed DER
inside it:

    u8      type          0x24 = certificate record
    u16 LE  msg_len       12 + 2 + len(DER) + 4
    u8[12]  record fields 01 00 70 00 03 00 00 06 00 04 01 00  (client's own)
    u16 LE  der_len       length of the DER that follows
    u8[..]  DER            X.509
    u8[4]   00 00 00 00    trailer

For the client's own record that is type 0x24, msg_len 0x02D5 (725) and
der_len 0x02C3 (707); 3 + 725 = 728 bytes on the wire, which is exactly what
logs/mp/medius.log shows.

The earlier reading here was "15-byte header | u16 LE length | DER | 0000 0000".
Same bytes, but it hard-coded the outer length, so choosing any certificate
other than the client's own (707 B) emitted a record whose outer length still
said 725 -- a framing error the client rejects on its own, before any
certificate comparison. Both lengths are now computed.

The *_an analysis found five certificates inside game/EBOOT.elf:

    0x10005C38  CN="#resistanceps3.online.scek.com 207440"  O=SCEK  (734 B)
    0x10005F18  CN="#resistanceps3.online.scej.com 207340"  O=SCEJ  (734 B)
    0x100061F8  CN="Resistance PS3 SCEE 207240"             O=SCEE  (719 B)
    0x100064C8  CN="i8 201740"                              O=SCEA  (707 B)  <- what the client sends
    0x10038310  two SCERT Group1 / Root Authority certs     (958 B)

So the console shipped the *server* certificates too, one per region -- the
client can compare the certificate we present against them.

    python tools/mp/make_reply.py scee      # -> logs/mp/reply.bin
    python tools/mp/make_reply.py scek
    python tools/mp/make_reply.py scej
    python tools/mp/make_reply.py client
    python tools/mp/make_reply.py scee --type 2   # record-fields byte 0 = 0x02
"""
import argparse
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CERT_EA = {
    "scek": 0x10005C38,
    "scej": 0x10005F18,
    "scee": 0x100061F8,
    "client": 0x100064C8,
}

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import medius_wire as w   # framing lives in medius_wire.py; see its docstring


def elf_bytes():
    path = os.path.join(ROOT, "game", "EBOOT.elf")
    return open(path, "rb").read()


def ea_to_off(ea):
    img = json.load(open(os.path.join(ROOT, "build_regen", "eboot_an", "EBOOT.image.json")))
    for s in img:
        va, fo, sz = int(s["vaddr"], 16), int(s["file_offset"], 16), int(s["filesz"], 16)
        if va <= ea < va + sz:
            return fo + (ea - va)
    raise SystemExit(f"EA 0x{ea:X} is not in a loadable segment")


def cert_der(name):
    data = elf_bytes()
    off = ea_to_off(CERT_EA[name])
    total = data[off + 2] << 8 | data[off + 3]
    return data[off:off + 4 + total]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cert", nargs="?", choices=sorted(CERT_EA),
                    help="certificate to embed (default: scee); not used with --payload")
    ap.add_argument("--type", type=lambda v: int(v, 0), default=None,
                    help="override record-fields byte 0 (0x01 in the client's request)")
    ap.add_argument("--msg-type", type=lambda v: int(v, 0), default=w.TYPE_CERT,
                    help="override the message type byte (0x24 in the client's request); "
                         "use with --out to build a sweep of candidates")
    ap.add_argument("--payload", default=None,
                    help="build a bare record instead of a certificate record: "
                         "type | u16 LE len | payload, all hex. This is the framing "
                         "the client itself uses for its non-certificate messages "
                         "(its 0x21 is 21 02 00 0E 01, its 0x23 is 23 20 00 | TLV), "
                         "so a reply to those is built this way, not with a DER.")
    ap.add_argument("--out", default="reply.bin",
                    help="file name inside logs/mp (default reply.bin; the server sends "
                         "reply.bin unless it is started with --rotate)")
    ap.add_argument("--header", default=None,
                    help="record fields as hex: 12 bytes, or the old 15-byte form whose "
                         "first three bytes are type + msg_len (the length is recomputed)")
    args = ap.parse_args()

    fields = bytearray(w.SCERT_FIELDS)
    if args.header:
        raw = bytes.fromhex(args.header.replace(" ", ""))
        if len(raw) == 15:
            if raw[0] != w.TYPE_CERT:
                raise SystemExit(f"type byte is 0x{raw[0]:02X}, expected 0x{w.TYPE_CERT:02X}")
            raw = raw[3:]           # drop type + msg_len; the rest are the fields
        if len(raw) != 12:
            raise SystemExit("header must be 12 record-field bytes (or the old 15-byte form)")
        fields = bytearray(raw)
    if args.type is not None:
        fields[0] = args.type & 0xFF

    if args.payload is not None:
        body = bytes.fromhex(args.payload.replace(" ", ""))
        if len(body) > 0xFFFF:
            raise SystemExit("payload too long for the u16 length field")
        typ = args.msg_type & 0xFF
        record = bytes([typ]) + len(body).to_bytes(2, "little") + body
        out = os.path.join(ROOT, "logs", "mp", args.out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out, "wb").write(record)
        print(f"bare record type 0x{typ:02X}, payload {len(body)} B, "
              f"record {len(record)} B -> {out}")
        return

    if args.cert is None:
        args.cert = "scee"
    der = cert_der(args.cert)
    record = w.encode_scert(der, bytes(fields), typ=args.msg_type & 0xFF)

    out = os.path.join(ROOT, "logs", "mp", args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "wb").write(record)
    print(f"{args.cert}: DER {len(der)} B, record {len(record)} B -> {out}")
    for line in w.describe(record, "  "):
        print(line)


if __name__ == "__main__":
    main()
