#!/usr/bin/env python3
"""Raw TCP listener that decodes a TLS/SSL ClientHello (v184).

R:FoM's SVO ticket login only accepts an https: TicketLoginURI and uses the
game's own SSL code (SSLSocket / rt_ssl, no cellSsl import). Before choosing
how to terminate it, record exactly what the client offers: record version,
hello version, cipher suites, compression, extensions. Logs to
logs/mp/tls_probe.log; never answers, so the client fails after logging.

    python tools/mp/tls_probe.py [port]     (default 10443)
"""
import os, socket, struct, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG = os.path.join(ROOT, 'logs', 'mp', 'tls_probe.log')
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10443


def log(*a):
    line = time.strftime('%H:%M:%S') + ' ' + ' '.join(str(x) for x in a)
    print(line, flush=True)
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def decode(data):
    if len(data) >= 2 and data[0] & 0x80 and data[2] == 1:   # SSLv2-framed hello
        n = ((data[0] & 0x7F) << 8) | data[1]
        ver = data[3:5].hex()
        cs_len, sid_len, ch_len = struct.unpack('>HHH', data[5:11])
        cs = data[11:11 + cs_len]
        suites = [cs[i:i + 3].hex() for i in range(0, len(cs), 3)]
        log(f'  SSLv2-framed ClientHello len={n} version={ver} suites({len(suites)})={suites}')
        return
    if len(data) < 9 or data[0] != 0x16:
        log('  not a TLS handshake record:', data[:32].hex(' '))
        return
    rver = data[1:3].hex()
    hs = data[5:]
    if hs[0] != 1:
        log(f'  handshake type {hs[0]} (not ClientHello)')
        return
    p = 4
    hver = hs[p:p + 2].hex(); p += 2 + 32
    sid = hs[p]; p += 1 + sid
    n = struct.unpack('>H', hs[p:p + 2])[0]; p += 2
    suites = [hs[p + i:p + i + 2].hex() for i in range(0, n, 2)]; p += n
    nc = hs[p]; comp = hs[p + 1:p + 1 + nc].hex(); p += 1 + nc
    ext = []
    if p + 2 <= len(hs):
        el = struct.unpack('>H', hs[p:p + 2])[0]; p += 2
        end = p + el
        while p + 4 <= end:
            t, l = struct.unpack('>HH', hs[p:p + 4]); ext.append(f'{t:04x}({l})'); p += 4 + l
    log(f'  record version {rver}, hello version {hver}, session id {sid} B')
    log(f'  cipher suites ({len(suites)}): {" ".join(suites)}')
    log(f'  compression: {comp}  extensions: {ext or "none"}')


def handle(c, a):
    log(f':{PORT} <- {a[0]}:{a[1]} CONNECTED')
    c.settimeout(10)
    try:
        data = c.recv(65536)
        log(f'  {len(data)} B: {data[:96].hex(" ")}')
        if data:
            decode(data)
        time.sleep(3)
    except OSError as e:
        log('  error', e)
    finally:
        c.close()
        log(f':{PORT} <- {a[0]}:{a[1]} CLOSED')


if __name__ == '__main__':
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', PORT)); s.listen(4)
    log(f'tls_probe listening on :{PORT}')
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()
