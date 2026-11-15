#!/usr/bin/env python3
"""Minimal SSL 3.0 HTTPS server for R:FoM's SVO ticket login (v184).

The game's rt_ssl (3.98, 2006) sends an SSLv2-framed ClientHello that asks
for SSL 3.0 and offers exactly one suite, SSL_RSA_WITH_RC4_128_MD5 (0x0004)
(logs/mp/tls_probe.log). Modern OpenSSL builds, Python's ssl included, cannot
speak SSL 3.0, so this file implements just that one handshake in pure Python:

    <- SSLv2-framed ClientHello (challenge = client random, left-padded)
    -> ServerHello(3.0, 0x0004) + Certificate + ServerHelloDone
    <- ClientKeyExchange (raw RSA block, no length prefix in SSL 3.0)
    <- ChangeCipherSpec, Finished (RC4 + SSLv3 MD5 MAC)
    -> ChangeCipherSpec, Finished
    <- application data: the HTTP request
    -> HTTP response, close_notify

Keys and certificates are generated once (data/svo_tls_key.json): a
stand-in for the game's embedded root (data/svo_root.der, patched into the
game with PS3_MEMPATCH=10038310:<path>, see "trust" below) and a 1024-bit
server leaf for CN=127.0.0.1 signed by it. SVO_TLS_CHAIN=1 sends leaf + root.

The HTTP answer for a path comes from data/svo/<path>.svml when that file
exists (same override scheme as svo_http.py), else an empty SVML page.
Log: data/svo_tls.log.

    python svo_tls.py [port]        (default 10443)
"""
import hashlib, json, os, random, socket, struct, sys, threading, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10443
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mp_config import PUBLIC_HOST, DATA_DIR   # noqa: E402
LOG = os.path.join(DATA_DIR, 'svo_tls.log')
KEYF = os.path.join(DATA_DIR, 'svo_tls_key.json')   # private keys: never commit
OVR = os.path.join(DATA_DIR, 'svo')
# Built-in answers. TicketLoginURI: status 20600 = login OK (the client then
# reports "SVO login succeeded with account id 1001").
BUILTIN_PAGES = {
    'TicketLoginURI': (b'<?xml version="1.0"?>\r\n<SVML>\r\n<SP_Login>\r\n'
                       b'<status><id>20600</id></status>\r\n<accountID>1001</accountID>\r\n'
                       b'<userContext>0</userContext>\r\n</SP_Login>\r\n</SVML>\r\n'),
}
# the certificate name follows the address clients are given (MP_PUBLIC_HOST)
CN = os.environ.get('SVO_TLS_CN', PUBLIC_HOST)

ALERTS = {0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac',
          30: 'decompression_failure', 40: 'handshake_failure', 41: 'no_certificate',
          42: 'bad_certificate', 43: 'unsupported_certificate', 44: 'certificate_revoked',
          45: 'certificate_expired', 46: 'certificate_unknown', 47: 'illegal_parameter',
          48: 'unknown_ca', 51: 'decrypt_error', 70: 'protocol_version'}


def log(*a):
    line = time.strftime('%H:%M:%S') + ' ' + ' '.join(str(x) for x in a)
    print(line, flush=True)
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


# --- RSA ---------------------------------------------------------------------
def _probable_prime(bits):
    rng = random.SystemRandom()
    small = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** .5) + 1, 2))]
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if any(n % p == 0 for p in small):
            continue
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2; s += 1
        for _ in range(40):
            a = rng.randrange(2, n - 2)
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                break
        else:
            return n


def gen_rsa(bits=1024, e=65537):
    while True:
        p, q = _probable_prime(bits // 2), _probable_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e and (p * q).bit_length() == bits:
            return p * q, e, pow(e, -1, phi)


# --- DER / X.509 -------------------------------------------------------------
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    return tlv(0x02, b)


SEQ = lambda *xs: tlv(0x30, b''.join(xs))
OID_RSA = bytes.fromhex('06092A864886F70D010101')
OID_SHA1RSA = bytes.fromhex('06092A864886F70D010105')
NULL = b'\x05\x00'


def name(cn):
    def rdn(oid, val):
        return tlv(0x31, SEQ(oid, tlv(0x13, val.encode())))
    return SEQ(rdn(bytes.fromhex('0603550406'), 'US'),
               rdn(bytes.fromhex('060355040A'), 'Local Test SVO'),
               rdn(bytes.fromhex('0603550403'), cn))


def sign_sha1(n, d, data):
    di = bytes.fromhex('3021300906052B0E03021A05000414') + hashlib.sha1(data).digest()
    k = (n.bit_length() + 7) // 8
    em = b'\x00\x01' + b'\xff' * (k - 3 - len(di)) + b'\x00' + di
    return pow(int.from_bytes(em, 'big'), d, n).to_bytes(k, 'big')


def make_cert(n, e, d, cn):
    alg = SEQ(OID_SHA1RSA, NULL)
    spki = SEQ(SEQ(OID_RSA, NULL), tlv(0x03, b'\x00' + SEQ(der_int(n), der_int(e))))
    validity = SEQ(tlv(0x17, b'050101000000Z'), tlv(0x17, b'491231235959Z'))
    tbs = SEQ(der_int(1), alg, name(cn), validity, name(cn), spki)    # X.509 v1
    return SEQ(tbs, alg, tlv(0x03, b'\x00' + sign_sha1(n, d, tbs)))


# --- trust: replace the game's embedded root ---------------------------------
# rt_ssl trusts exactly one root, the 958-byte "SCERT Root Authority" cert
# embedded in the EBOOT (file 0x7B8310, VA 0x10038310; loaded by the rt_ssl
# setup around func_00670170 via func_00670488(ctx, cert, 0x3BE)). With a
# self-signed server cert the client read our whole first flight and then went
# silent (logs/net_trace.log: recv 580 B on the TLS socket, nothing after).
#
# So: build a stand-in root with the SAME names, serial size and validity but
# our own 2048-bit key -- it comes out at exactly 958 bytes, matching the
# hard-coded length -- and PS3_MEMPATCH it over the original at load time
# (data/svo_root.der). The server presents a leaf for CN=127.0.0.1 signed by
# that root, as the real SVO server presumably did with Sony's.
ROOT_FILE_OFF, ROOT_VA, ROOT_LEN = 0x7B8310, 0x10038310, 958
ROOT_DER = os.path.join(DATA_DIR, 'svo_root.der')


def _der_items(b, i, end):
    out = []
    while i < end:
        t, l, h = b[i], b[i + 1], 2
        if l & 0x80:
            k = l & 0x7F; l = int.from_bytes(b[i + 2:i + 2 + k], 'big'); h = 2 + k
        out.append((t, b[i:i + h + l], i + h, i + h + l))
        i += h + l
    return out


# Public fields of the game's embedded root (EBOOT.elf file offset 0x7B8310):
# serial length, issuer Name and validity, copied so the stand-in root has the
# same shape (and size) without the server needing the game files.
ORIG_SERIAL_LEN = 20
ORIG_ISSUER = bytes.fromhex(
    '308196310b3009060355040613025553310b3009060355040813024341311230100603550407130953616e20446965'
    '676f3131302f060355040a1328534f4e5920436f6d707574657220456e7465727461696e6d656e7420416d65726963'
    '6120496e632e31143012060355040b130b53434552542047726f7570311d301b06035504031314534345525420526f'
    '6f7420417574686f72697479')
ORIG_VALIDITY = bytes.fromhex('301e170d3035303130313132303030305a170d3334313233313233353935395a')


def original_root_parts():
    """-> (serial_len, issuer Name DER, validity DER) of the game's root."""
    return ORIG_SERIAL_LEN, ORIG_ISSUER, ORIG_VALIDITY


def make_root(n, e, d):
    slen, issuer, validity = original_root_parts()
    alg = SEQ(OID_SHA1RSA, NULL)
    spki = SEQ(SEQ(OID_RSA, NULL), tlv(0x03, b'\x00' + SEQ(der_int(n), der_int(e))))
    serial = tlv(0x02, b'\x01' + os.urandom(slen - 1))
    tbs = SEQ(tlv(0xA0, der_int(2)), serial, alg, issuer, validity, issuer, spki)   # v3, self-signed
    return SEQ(tbs, alg, tlv(0x03, b'\x00' + sign_sha1(n, d, tbs))), issuer


def make_leaf(n, e, issuer, rn, rd, cn):
    alg = SEQ(OID_SHA1RSA, NULL)
    spki = SEQ(SEQ(OID_RSA, NULL), tlv(0x03, b'\x00' + SEQ(der_int(n), der_int(e))))
    validity = SEQ(tlv(0x17, b'060101000000Z'), tlv(0x17, b'341231235959Z'))
    tbs = SEQ(tlv(0xA0, der_int(2)), der_int(2), alg, issuer, validity, name(cn), spki)
    return SEQ(tbs, alg, tlv(0x03, b'\x00' + sign_sha1(rn, rd, tbs)))


def load_key():
    if os.path.exists(KEYF):
        k = json.load(open(KEYF))
        if k.get('cn') == CN and k.get('root') and os.path.exists(ROOT_DER):
            return int(k['n'], 16), int(k['e']), int(k['d'], 16), bytes.fromhex(k['cert'])
    while True:
        log('generating 2048-bit root key...')
        rn, re_, rd = gen_rsa(2048)
        root, issuer = make_root(rn, re_, rd)
        if len(root) == ROOT_LEN:
            break
        log(f'  root came out {len(root)} B, need {ROOT_LEN}; retrying')
    log('generating 1024-bit server key...')
    n, e, d = gen_rsa()
    cert = make_leaf(n, e, issuer, rn, rd, CN)
    open(ROOT_DER, 'wb').write(root)
    json.dump({'n': f'{n:x}', 'e': e, 'd': f'{d:x}', 'cn': CN, 'cert': cert.hex(),
               'root': root.hex(), 'root_n': f'{rn:x}'}, open(KEYF, 'w'))
    log(f'wrote {ROOT_DER} ({len(root)} B): launch with PS3_MEMPATCH={ROOT_VA:08X}:<that path>')
    return n, e, d, cert


# --- RC4 / SSLv3 primitives --------------------------------------------------
class RC4:
    def __init__(self, key):
        S = list(range(256)); j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self.S, self.i, self.j = S, 0, 0

    def __call__(self, data):
        S, i, j = self.S, self.i, self.j
        out = bytearray(len(data))
        for k, c in enumerate(data):
            i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[k] = c ^ S[(S[i] + S[j]) & 0xFF]
        self.i, self.j = i, j
        return bytes(out)


MD5, SHA1 = hashlib.md5, hashlib.sha1
PAD1_MD5, PAD2_MD5 = b'\x36' * 48, b'\x5c' * 48
PAD1_SHA, PAD2_SHA = b'\x36' * 40, b'\x5c' * 40


def ssl3_prf(secret, r1, r2, n):
    out, i = b'', 0
    while len(out) < n:
        label = bytes([0x41 + i]) * (i + 1)
        out += MD5(secret + SHA1(label + secret + r1 + r2).digest()).digest()
        i += 1
    return out[:n]


def ssl3_mac(secret, seq, ctype, data):
    inner = MD5(secret + PAD1_MD5 + struct.pack('>QBH', seq, ctype, len(data)) + data).digest()
    return MD5(secret + PAD2_MD5 + inner).digest()


def finished_hash(msgs, master, sender):
    md5 = MD5(master + PAD2_MD5 + MD5(msgs + sender + master + PAD1_MD5).digest()).digest()
    sha = SHA1(master + PAD2_SHA + SHA1(msgs + sender + master + PAD1_SHA).digest()).digest()
    return md5 + sha


def hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, 'big') + body


# --- connection --------------------------------------------------------------
class Conn:
    def __init__(self, sock, key):
        self.s, (self.n, self.e, self.d, self.cert) = sock, key
        self.buf = b''
        self.rd = self.wr = None          # (rc4, mac_secret)
        self.rseq = self.wseq = 0

    def _fill(self, n):
        while len(self.buf) < n:
            c = self.s.recv(65536)
            if not c:
                raise EOFError('client closed')
            self.buf += c

    def _take(self, n):
        self._fill(n)
        b, self.buf = self.buf[:n], self.buf[n:]
        return b

    def read_record(self):
        h = self._take(5)
        t, ver, ln = h[0], h[1:3], struct.unpack('>H', h[3:5])[0]
        data = self._take(ln)
        if self.rd:
            rc4, sec = self.rd
            plain = rc4(data)
            body, mac = plain[:-16], plain[-16:]
            ok = ssl3_mac(sec, self.rseq, t, body) == mac
            self.rseq += 1
            if not ok:
                log('  !! bad record MAC from client')
            data = body
        if t == 21:
            log(f'  <- ALERT level {data[0]} {ALERTS.get(data[1], data[1])}')
        return t, data

    def write_record(self, t, data):
        if self.wr:
            rc4, sec = self.wr
            data = rc4(data + ssl3_mac(sec, self.wseq, t, data))
            self.wseq += 1
        self.s.sendall(bytes([t]) + b'\x03\x00' + struct.pack('>H', len(data)) + data)

    def handshake(self):
        first = self._take(2)
        msgs = b''
        if first[0] & 0x80:                                   # SSLv2-framed hello
            ln = ((first[0] & 0x7F) << 8) | first[1]
            body = self._take(ln)
            msgs += body
            cs_len, sid_len, ch_len = struct.unpack('>HHH', body[3:9])
            off = 9 + cs_len + sid_len
            ch = body[off:off + ch_len]
            client_random = ch.rjust(32, b'\x00')[-32:]
            log(f'  <- v2 ClientHello ver {body[1:3].hex()} suites {body[9:9+cs_len].hex()}')
        else:                                                 # SSLv3 record hello
            self.buf = first + self.buf
            t, body = self.read_record()
            msgs += body
            client_random = body[4 + 2:4 + 34]
            log(f'  <- v3 ClientHello {body[:48].hex()}')

        server_random = struct.pack('>I', int(time.time())) + os.urandom(28)
        sh = hs(2, b'\x03\x00' + server_random + b'\x20' + os.urandom(32) + b'\x00\x04' + b'\x00')
        chain = [self.cert]
        if os.environ.get('SVO_TLS_CHAIN') == '1' and os.path.exists(ROOT_DER):
            chain.append(open(ROOT_DER, 'rb').read())        # leaf + root
        lst = b''.join(len(c).to_bytes(3, 'big') + c for c in chain)
        cert = hs(11, len(lst).to_bytes(3, 'big') + lst)
        done = hs(14, b'')
        out = sh + cert + done
        msgs += out
        self.write_record(22, out)
        log(f'  -> ServerHello + Certificate ({len(self.cert)} B) + ServerHelloDone')

        # ClientKeyExchange (may share a record with CCS/Finished)
        t, data = self.read_record()
        if t != 22 or data[0] != 16:
            log(f'  expected ClientKeyExchange, got record {t} {data[:16].hex()}')
            return False
        n = int.from_bytes(data[1:4], 'big')
        cke = data[:4 + n]
        rest = data[4 + n:]
        msgs += cke
        enc = cke[4:]
        k = (self.n.bit_length() + 7) // 8
        if len(enc) == k + 2 and int.from_bytes(enc[:2], 'big') == k:
            enc = enc[2:]
        em = pow(int.from_bytes(enc, 'big'), self.d, self.n).to_bytes(k, 'big')
        if em[:2] != b'\x00\x02' or b'\x00' not in em[2:]:
            log('  !! premaster decrypt: bad PKCS#1 padding', em[:8].hex())
            return False
        pms = em[em.index(b'\x00', 2) + 1:]
        log(f'  <- ClientKeyExchange, premaster {len(pms)} B ver {pms[:2].hex()}')
        master = ssl3_prf(pms, client_random, server_random, 48)
        kb = ssl3_prf(master, server_random, client_random, 64)
        cmac, smac, ckey, skey = kb[0:16], kb[16:32], kb[32:48], kb[48:64]

        if rest:
            log('  (extra handshake bytes after CKE ignored)', rest.hex())
        t, data = self.read_record()
        if t != 20:
            log(f'  expected ChangeCipherSpec, got {t} {data[:16].hex()}')
            return False
        self.rd, self.rseq = (RC4(ckey), cmac), 0
        t, data = self.read_record()
        if t != 22 or data[0] != 20:
            log(f'  expected Finished, got {t} {data[:16].hex()}')
            return False
        want = finished_hash(msgs, master, b'CLNT')
        log('  <- client Finished', 'OK' if data[4:] == want else 'MISMATCH')
        msgs += data
        self.write_record(20, b'\x01')
        self.wr, self.wseq = (RC4(skey), smac), 0
        self.write_record(22, hs(20, finished_hash(msgs, master, b'SRVR')))
        log('  -> ChangeCipherSpec + Finished: handshake complete')
        return True

    def read_http(self):
        req = b''
        while b'\r\n\r\n' not in req:
            t, data = self.read_record()
            if t != 23:
                return None
            req += data
        head, _, body = req.partition(b'\r\n\r\n')
        cl = 0
        for line in head.split(b'\r\n')[1:]:
            if line.lower().startswith(b'content-length:'):
                cl = int(line.split(b':', 1)[1])
        while len(body) < cl:
            t, data = self.read_record()
            if t != 23:
                break
            body += data
        return head, body


def handle(c, a, key):
    log(f':{PORT} <- {a[0]}:{a[1]} CONNECTED')
    c.settimeout(30)
    conn = Conn(c, key)
    try:
        if not conn.handshake():
            return
        r = conn.read_http()
        if not r:
            log('  no HTTP request')
            return
        head, body = r
        for line in head.split(b'\r\n'):
            log('   ', line.decode('latin-1'))
        if body:
            log('    body', repr(body[:4000]))
        path = head.split(b' ')[1].decode('latin-1').split('?')[0]
        k = path.strip('/').replace('/', '_') or 'index'
        ovr = os.path.join(OVR, k + '.svml')
        page = open(ovr, 'rb').read() if os.path.exists(ovr) else BUILTIN_PAGES.get(k, b'<SVML>\n</SVML>\n')
        resp = (b'HTTP/1.1 200 OK\r\nContent-Type: text/svml\r\nContent-Length: '
                + str(len(page)).encode() + b'\r\nConnection: close\r\n\r\n' + page)
        conn.write_record(23, resp)
        log(f'  -> 200, {len(page)} B', '(override)' if os.path.exists(ovr) else '(built-in)')
        conn.write_record(21, b'\x01\x00')
    except (EOFError, OSError) as e:
        log('  ended:', e)
    finally:
        c.close()
        log(f':{PORT} <- {a[0]}:{a[1]} CLOSED')


if __name__ == '__main__':
    key = load_key()
    log(f'svo_tls (SSL 3.0, RC4-128-MD5) listening on :{PORT}, cert CN={CN}, {len(key[3])} B')
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', PORT)); s.listen(8)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a, key), daemon=True).start()
