#!/usr/bin/env python3
"""Multiplayer: port tap.

Resistance's Medius client picks its own ports, and until we see one we do not
know which to listen on. This binds a spread of plausible ports, accepts
anything that arrives, and writes what the client sent (hex + printable) to
logs/mp/tap.log so the first connection can be identified from one click.

    python tools/mp/tap.py [--udp]

Nothing here is part of the port; it is a probe.
"""
import argparse
import datetime
import os
import socket
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG = os.path.join(ROOT, "logs", "mp", "tap.log")

# Medius / SVO era ports, plus the obvious web ones and the port the port's own
# psnr server uses (in case something tries it).
PORTS = list(range(10000, 10101)) + [80, 443, 5223, 3480, 3658, 36100, 27900, 28910, 29900]


def log(line):
    stamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{stamp} {line}\n")
        f.flush()
    print(f"{stamp} {line}", flush=True)


def hexdump(data, limit=192):
    d = data[:limit]
    for off in range(0, len(d), 16):
        chunk = d[off:off + 16]
        hx = " ".join(f"{b:02X}" for b in chunk)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        log(f"  {off:04X}  {hx:<47}  {txt}")
    if len(data) > limit:
        log(f"  ... {len(data)} bytes total")


def serve_tcp(sock, port):
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            return
        threading.Thread(target=handle_tcp, args=(conn, addr, port), daemon=True).start()


def handle_tcp(conn, addr, port):
    log(f"TCP :{port} <- {addr[0]}:{addr[1]}  CONNECTED")
    conn.settimeout(30)
    total = 0
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            total += len(data)
            log(f"TCP :{port} <- {addr[0]}:{addr[1]}  {len(data)} bytes (total {total})")
            hexdump(data)
    except socket.timeout:
        log(f"TCP :{port} <- {addr[0]}:{addr[1]}  idle 30 s")
    except OSError as e:
        log(f"TCP :{port} <- {addr[0]}:{addr[1]}  error {e}")
    finally:
        log(f"TCP :{port} <- {addr[0]}:{addr[1]}  CLOSED after {total} bytes")
        conn.close()


def serve_udp(sock, port):
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return
        log(f"UDP :{port} <- {addr[0]}:{addr[1]}  {len(data)} bytes")
        hexdump(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--udp", action="store_true", help="also bind UDP on the same ports")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    open(LOG, "w").close()
    log(f"tap starting: TCP {PORTS[0]}..{PORTS[-1]}")

    bound = []
    for port in PORTS:
        for kind, fn in (("tcp", serve_tcp), ("udp", serve_udp)):
            if kind == "udp" and not args.udp:
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
            except OSError:
                s.close()
                continue
            if kind == "tcp":
                s.listen(8)
            bound.append((kind, port))
            threading.Thread(target=fn, args=(s, port), daemon=True).start()

    log(f"listening on {len(bound)} sockets")
    threading.Event().wait()


if __name__ == "__main__":
    main()
