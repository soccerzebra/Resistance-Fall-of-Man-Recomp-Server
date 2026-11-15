#!/usr/bin/env python3
"""Local DME (game) server -- phase 2 (v185). See README.md.

The DME is the SCE-RT relay every player of one game connects to (the match
itself runs on the players' PS3s). The numbering of RT records matches the
standard SCE-RT set, and every layout below was read from the client's own
handler (rt_msg_client 3.98, handler table 0x62BF00):

  client -> server                        server -> client
  0x24 HELLO (cert)                       0x25 HELLO          u16 version 398
  0x23 CONNECT_READY_REQUIRE (password)   0x22 CONNECT_REQUIRE
  0x00 CONNECT_TCP  u32 world, u16 app, keys
  0x21 CONNECT_READY_TCP                  0x07 CONNECT_ACCEPT_TCP
                                               u16 my index, u32 scert id,
                                               u16 player count, char ip[16]
                                          0x1A CONNECT_COMPLETE  u16 count
                                          0x08 CONNECT_NOTIFY (86 B)
                                               u16 idx, u32 scert, ip[16], key[64]
                                          0x09 DISCONNECT_NOTIFY (22 B)
                                               u16 idx, u32 scert, ip[16]
  0x02 APP_BROADCAST  data                0x02/03/04/0x32-0x36 relayed app msg:
  0x03 APP_SINGLE     u16 target, data         u16 source index, data
  0x04 APP_LIST       u8 n, mask[n], data   (func_006282C8; 0x0A = from server,
  0x32-0x34 the same, QoS variants           no source index)
  0x2D TIMEBASE_QUERY u32 client ms       0x2E TIMEBASE_QUERY_NOTIFY
                                               u32 client ms (echo), u32 server ms
  0x05 ECHO, 0x0D SET_RECV_FLAG, 0x0B app (Medius) -> logged
                                          0x1F ping (keeps the 3 s timer alive)

Aux UDP (the lobby's JoinGame reply says ClientServerTCPAuxUDP, type 3):
  0x15 CONNECT_TCP_AUX_UDP (as 0x00)      0x07 CONNECT_ACCEPT_TCP
  0x21 CONNECT_READY_TCP                  0x18 SERVER_INFO_AUX_UDP
                                               ip[16], u16 port  (func_0062A82C)
  UDP 0x16 CONNECT_AUX_UDP (32 B):        UDP 0x19 CONNECT_ACCEPT_AUX_UDP (26 B)
       u32 world @0, u16 index @0x1A,          u16 index, u32 scert (both must
       scert @0x1C   (func_0062A6C4)           match 0x07), u16 count, ip[16],
                                               u16 port  (func_0062AE84)
  0x17 CONNECT_READY_AUX_UDP (on TCP)     0x1A CONNECT_COMPLETE (TCP), notifies
Afterwards app messages may arrive on either socket; each is relayed to the
other players over UDP when they have an aux UDP address, else over TCP.

The handshake keeps the exact record order the lobby server proved
(0x03/04/05 junk records excepted -- they were app messages from source 1).
DME_ORDER=canned replays the old lobby prefix verbatim as a fallback.

    python dme/dme_server.py [port]      (default 10079, TCP and UDP)
"""
import os, socket, struct, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from mp_config import REPLY_DIR, DATA_DIR, PUBLIC_HOST   # noqa: E402
LOGDIR = REPLY_DIR                         # canned records
LOG = os.path.join(DATA_DIR, 'dme.log')
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10079
PING_GAP = float(os.environ.get('DME_PING_GAP', '0.6'))
FIRST_INDEX = int(os.environ.get('DME_FIRST_INDEX', '0'))
ORDER = os.environ.get('DME_ORDER', 'clean')
LOCK = threading.RLock()
T0 = time.time()
WORLDS = {}          # world id -> {index: Client}
UDP = None           # the aux UDP socket (same port as TCP)
BY_UDP = {}          # (ip, port) -> Client


def log(*a):
    line = time.strftime('%H:%M:%S') + f'.{int(time.time() * 1000) % 1000:03d} ' + ' '.join(str(x) for x in a)
    with LOCK:
        print(line, flush=True)
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line + '\n')


def rec(t, body=b''):
    return bytes([t]) + struct.pack('<H', len(body)) + body


def canned(name):
    return open(os.path.join(LOGDIR, name), 'rb').read()


def ip16(ip):
    return ip.encode()[:15].ljust(16, b'\0')


def server_ms():
    return int((time.time() - T0) * 1000) & 0xFFFFFFFF


class Client:
    def __init__(self, conn, addr):
        self.conn, self.addr = conn, addr
        self.idx = None
        self.world = None
        self.scert = 0
        self.wlock = threading.Lock()
        self.last_tx = time.time()
        self.aux = False         # connected with 0x15: wants the aux UDP channel
        self.udp = None          # its UDP address once 0x16 arrived
        self.complete = False    # 0x1A sent

    def send(self, data, what=''):
        with self.wlock:
            self.conn.sendall(data)
            self.last_tx = time.time()
        if what:
            log(f'  -> [{self.idx}] {what} ({len(data)} B)')

    def send_udp(self, data, what=''):
        UDP.sendto(data, self.udp)
        if what:
            log(f'  -> [{self.idx}] udp {what} ({len(data)} B)')

    def send_fast(self, data):
        """App traffic: the aux UDP channel when the client has one."""
        if self.udp:
            self.send_udp(data)
        else:
            self.send(data)

    def tag(self):
        return f'[{self.idx if self.idx is not None else "?"} {self.addr[1]}]'


def members(world):
    return WORLDS.get(world, {})


def join_world(c, world):
    with LOCK:
        m = WORLDS.setdefault(world, {})
        i = FIRST_INDEX
        while i in m:
            i += 1
        c.idx, c.world, c.scert = i, world, 0x1000 + i
        m[i] = c
        return i, len(m)


def leave_world(c):
    with LOCK:
        m = WORLDS.get(c.world)
        if not m or m.get(c.idx) is not c:
            return []
        del m[c.idx]
        if c.udp:
            BY_UDP.pop(c.udp, None)
        others = list(m.values())
        if not m:
            del WORLDS[c.world]
    note = rec(0x09, struct.pack('<HI', c.idx, c.scert) + ip16(c.addr[0]))
    for o in others:
        try:
            o.send(note, f'0x09 DISCONNECT_NOTIFY idx {c.idx}')
        except OSError:
            pass
    return others


def connect_notify(c):
    return rec(0x08, struct.pack('<HI', c.idx, c.scert) + ip16(c.addr[0]) + b'\0' * 64)


def complete_connect(c):
    """0x1A CONNECT_COMPLETE, then the CONNECT_NOTIFYs both ways."""
    n = len(members(c.world))
    c.send(rec(0x1A, struct.pack('<H', n)), f'0x1A CONNECT_COMPLETE count {n}')
    c.complete = True
    for i, o in list(members(c.world).items()):
        if o is c:
            continue
        c.send(connect_notify(o), f'0x08 CONNECT_NOTIFY (existing idx {i})')
        try:
            o.send(connect_notify(c), f'0x08 CONNECT_NOTIFY (new idx {c.idx})')
        except OSError:
            pass


def relay(c, t, body, via_udp=False):
    """App messages between players. Delivered as the same record type with
    the sender's index prefixed (the client's 0x02/03/04 receive path)."""
    others = {i: o for i, o in members(c.world).items() if o is not c}
    src = struct.pack('<H', c.idx)
    out_t = t
    if t in (0x02, 0x32):
        targets, data = list(others.values()), body
    elif t in (0x03, 0x33):
        if len(body) < 2:
            return
        tgt = struct.unpack_from('<H', body)[0]
        targets, data = [o for i, o in others.items() if i == tgt], body[2:]
    elif t in (0x04, 0x34):
        n = body[0] if body else 0
        mask, data = body[1:1 + n], body[1 + n:]
        want = {b * 8 + k for b in range(len(mask)) for k in range(8) if mask[b] >> k & 1}
        targets = [o for i, o in others.items() if i in want]
        out_t = 0x03 if t == 0x04 else 0x33
    else:
        return
    for o in targets:
        try:
            # what came in reliable (TCP) stays reliable; UDP traffic goes out
            # over UDP to every player that has the channel
            if via_udp:
                o.send_fast(rec(out_t, src + data))
            else:
                o.send(rec(out_t, src + data))
        except OSError:
            pass
    if not via_udp:
        log(f'  relay {c.tag()} 0x{t:02X} {len(data)} B -> {[o.idx for o in targets]}')


def parse(buf):
    out = []
    while len(buf) >= 3:
        n = struct.unpack_from('<H', buf, 1)[0]
        if len(buf) < 3 + n:
            break
        out.append((buf[0], buf[3:3 + n]))
        buf = buf[3 + n:]
    return out, buf


def handle(conn, addr):
    c = Client(conn, addr)
    # v185: the game sends small records (23 B state updates every ~150 ms);
    # Nagle + delayed ACK would hold them back by up to ~200 ms per hop.
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log(f'TCP :{PORT} <- {addr[0]}:{addr[1]} CONNECTED')
    conn.settimeout(PING_GAP)
    buf = b''
    try:
        while True:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                if c.complete:
                    c.send(rec(0x1F))
                continue
            if not data:
                break
            recs, buf = parse(buf + data)
            for t, body in recs:
                if t not in (0x1F,):
                    log(f'  <- {c.tag()} 0x{t:02X} len {len(body)}: {body[:48].hex(" ")}')
                if t == 0x24:                                  # HELLO
                    if ORDER == 'canned':
                        for n in ('reply_0x07.bin', 'reply_0x22.bin', 'reply_0x25_g.bin',
                                  'reply_0x2A_a.bin'):
                            c.send(canned(n), n)
                    else:
                        c.send(canned('reply_0x22.bin'), '0x22 CONNECT_REQUIRE')
                        c.send(rec(0x25, struct.pack('<H', 398)), '0x25 HELLO 398')
                elif t in (0x00, 0x15):                        # CONNECT_TCP (0x15: + aux UDP)
                    # body: u32 world, u16 app id (0x4ECE), keys (seen: 07 00 00 00 CE 4E)
                    world = struct.unpack_from('<I', body, 0)[0] if len(body) >= 4 else 0
                    idx, n = join_world(c, world)
                    c.aux = t == 0x15
                    log(f'  {c.tag()} joined world {world} as index {idx} ({n} in game)'
                        f'{" with aux UDP" if c.aux else ""}')
                    c.send(rec(0x07, struct.pack('<HIH', idx, c.scert, n) + ip16(addr[0])),
                           f'0x07 CONNECT_ACCEPT idx {idx} count {n}')
                elif t == 0x21:                                # CONNECT_READY_TCP
                    if c.aux:
                        # where to connect the aux UDP channel; 0x1A follows its 0x17
                        c.send(rec(0x18, ip16(PUBLIC_HOST) + struct.pack('<H', PORT)),
                               f'0x18 SERVER_INFO_AUX_UDP {PUBLIC_HOST}:{PORT}')
                    else:
                        complete_connect(c)
                elif t == 0x17:                                # CONNECT_READY_AUX_UDP (arrives on TCP)
                    if not c.complete:
                        complete_connect(c)
                elif t == 0x2D and len(body) >= 4:             # TIMEBASE_QUERY
                    c.send(rec(0x2E, body[:4] + struct.pack('<I', server_ms())))
                elif t in (0x02, 0x03, 0x04, 0x32, 0x33, 0x34):
                    relay(c, t, body)
    except OSError as e:
        log(f'  {c.tag()} error {e}')
    finally:
        log(f'TCP :{PORT} <- {addr[0]}:{addr[1]} {c.tag()} CLOSED')
        leave_world(c)
        conn.close()


def udp_connect(a, p):
    """UDP 0x16: tie this address to the player's TCP connection, answer 0x19."""
    if len(p) < 0x1E:
        log(f'udp<- {a[0]}:{a[1]} 0x16 too short ({len(p)} B)')
        return
    world = struct.unpack_from('<I', p, 0)[0]
    idx = struct.unpack_from('<H', p, 0x1A)[0]
    with LOCK:
        c = members(world).get(idx)
        if c:
            if c.udp:
                BY_UDP.pop(c.udp, None)
            c.udp = a
            BY_UDP[a] = c
    if not c:
        log(f'udp<- {a[0]}:{a[1]} 0x16 for world {world} index {idx}: no such player')
        return
    n = len(members(world))
    c.send_udp(rec(0x19, struct.pack('<HIH', idx, c.scert, n) + ip16(a[0]) + struct.pack('<H', a[1])),
               f'0x19 CONNECT_ACCEPT_AUX_UDP idx {idx} ({a[0]}:{a[1]})')


def udp_loop(s):
    while True:
        try:
            d, a = s.recvfrom(65536)
        except OSError:
            continue        # Windows: ICMP port-unreachable from a gone client
        recs, rest = parse(d)
        c = BY_UDP.get(a)
        for t, p in recs:
            if t == 0x16:
                log(f'udp<- {a[0]}:{a[1]} 0x16 CONNECT_AUX_UDP: {p[:32].hex(" ")}')
                udp_connect(a, p)
            elif not c:
                log(f'udp<- {a[0]}:{a[1]} 0x{t:02X} from an unknown address, dropped')
            elif t == 0x17:                                    # CONNECT_READY_AUX_UDP
                log(f'udp<- {c.tag()} 0x17 CONNECT_READY_AUX_UDP')
                if not c.complete:
                    complete_connect(c)
            elif t in (0x02, 0x03, 0x04, 0x32, 0x33, 0x34):
                relay(c, t, p, via_udp=True)
            elif t != 0x1F:
                log(f'udp<- {c.tag()} 0x{t:02X} len {len(p)}: {p[:48].hex(" ")}')
        if rest:
            log(f'udp<- {a[0]}:{a[1]} {len(rest)} B unframed: {rest[:64].hex(" ")}')


if __name__ == '__main__':
    t = socket.socket()
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(('0.0.0.0', PORT)); t.listen(16)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(('0.0.0.0', PORT))
    UDP = u
    threading.Thread(target=udp_loop, args=(u,), daemon=True).start()
    log(f'dme_server listening TCP+UDP :{PORT} (order {ORDER}, first index {FIRST_INDEX}, '
        f'aux UDP address {PUBLIC_HOST}:{PORT})')
    while True:
        cc, aa = t.accept()
        threading.Thread(target=handle, args=(cc, aa), daemon=True).start()
