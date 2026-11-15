#!/usr/bin/env python3
"""Multiplayer: Medius server, v0 -- capture and reply.

What the client does today (logs/mp/tap.log, 18:37:35):

    connect  127.0.0.1:10071                     <- resistance.ps3.online.scea.com
    send     728 bytes                           <- SCERT certificate exchange, PLAINTEXT
             24 D5 02 01 00 70 00 03 00 00 06 00 04 01 00 C3 02
             30 82 02 BF 30 82 01 A7 A0 03 02 01 02 02 14 ...   <- X.509, 0x02BF = 703
             (subject: C=US, ST=CA, L=San Diego,
                       O=SONY Computer Entertainment America Inc.,
                       OU=SCERT Group1)
    (30 s of silence)
    send     20 01 00 01                         <- gives up
    close

So: no TLS on this socket. The client presents its own SCERT certificate
first, as a length-prefixed record, and waits for the server's reply. No
`16 03` anywhere means the transport is plaintext and the security lives in
the SCERT exchange.

This script is not the server. It is the instrument: it accepts, records every
byte in both directions with timestamps, and -- so we can find out what the
client wants -- will send back whatever is in logs/mp/reply.bin if that file
exists when a connection arrives (it is re-read per connection, so a reply can
be changed without restarting).

    python medius_server.py [--ports 10071,10072]

Log: data/medius.log (canned records: replies/)
"""
import argparse
import datetime
import hashlib
import glob
import os
import socket
import struct
import threading
import time

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mp_config import REPLY_DIR, DATA_DIR   # noqa: E402
# canned records (reply_*.bin) come from replies/; the log goes to data/
LOGDIR = REPLY_DIR
LOG = os.path.join(DATA_DIR, "medius.log")
REPLY = os.path.join(LOGDIR, "reply.bin")
import medius_wire as w   # framing lives in medius_wire.py; see its docstring

LOCK = threading.Lock()
DRIP = [0, 0.15]   # chunk bytes, seconds between chunks
ROTATE = [False]   # --rotate: hand out the next reply*.bin per connection
ROT_IDX = [0]
SWEEP = [False]    # --sweep: try candidates on ONE connection, one per gap
SWEEP_GAP = [float(os.environ.get('SWEEP_GAP', '0.15'))]
# SWEEP_ONE=<n>: send the verified prefix up to and including reply_0x1A_s, then
# exactly ONE candidate (index n of the post-prefix order) and nothing more.
#
# The stream sweep cannot work past 0x1A: the client dispatched only the first
# post-prefix record (0x1B, trace kind=4 b=0x08) and then ignored every later
# record, because it is waiting for a specific reply and treats our subsequent
# bytes as the rest of that record. One candidate per connection costs a click
# per candidate, which is fine now that the loop is automated.
SWEEP_ONE = [int(os.environ.get('SWEEP_ONE', '-1'))]
# SWEEP_DUPLEX=echo|hash: after the client answers a candidate with a digest
# record, answer IT with a record of the same type, in the layout the client
# itself used:
#   type | u16 len | 01 | u32 12744 | u32 0 | u32 16 | digest[16]
# echo = hand its own digest back; hash = hand back sha1(its digest)[:16].
# Motivation: in state 0x08 reply_0x1D_any made the client send exactly that
# shape carrying sha1("")[:16], i.e. it digests an input and answers; the
# plausible next step is us proving we followed along.
SWEEP_DUPLEX = [os.environ.get('SWEEP_DUPLEX', '').strip().lower()]
# SWEEP_AFTER=<reply_*.bin>: after the digest exchange completes, send that record
# on the same connection. The digest step is an anti-cheat ping (0x1D: addr+nbytes
# -> client returns sha1 of that guest range), so anything the client ignored in
# state 0x08 was ignored *before* the ping was satisfied. This is how to re-test
# those candidates with the ping done.
SWEEP_AFTER = [os.environ.get('SWEEP_AFTER', '').strip()]
# SWEEP_ONLY=reply_0xNN_echo.bin: prefix + exactly this record. For testing one
# hand-built body against one type without renumbering the candidate order.
SWEEP_ONLY = [os.environ.get('SWEEP_ONLY', '').strip()]
# SWEEP_KEEPALIVE="<reply_file>:<interval_s>:<count>": after the last candidate,
# keep sending that record on a fixed interval. Tests whether the client's 3 s
# give-up is an inactivity timeout (client stops giving up) or a specific missing
# record (it gives up anyway).
SWEEP_KEEPALIVE = [os.environ.get('SWEEP_KEEPALIVE', '').strip()]
# SWEEP_PACED=<ping_file>: the client's 3 s give-up is an INACTIVITY timeout
# (verified: a ping train kept it alive through 16 pings, closing only 2.5 s after
# the last), so a session can be held open and many candidates tested in ONE
# connection -- send candidate, wait, send ping, wait, next. A ping reply
# ("1f 00 00") is not a reaction and is filtered out.
SWEEP_PACED = [os.environ.get('SWEEP_PACED', '').strip()]
SWEEP_PACED_GAP = [float(os.environ.get('SWEEP_PACED_GAP', '0.6'))]
# SWEEP_LIST=a.bin,b.bin,...: explicit ordered candidate files for the paced
# sweep. The default list is the 25 hand-staged records; the body-variant corpus
# is far larger and needs an order that keeps killing records out of the way.
SWEEP_LIST = [x.strip() for x in os.environ.get('SWEEP_LIST', '').split(',') if x.strip()]
SWEEP_DIGEST_ADDR = [int(os.environ.get('SWEEP_DIGEST_ADDR', '0'), 0)]
SWEEP_DIGEST_LEN = [int(os.environ.get('SWEEP_DIGEST_LEN', '0'), 0)]
# The client gives up 30 s after its certificate. At 0.6 s per candidate that is
# ~45 sends, minus the ~3 s the verified prefix costs -- so 33 is the honest
# ceiling and everything past it would be cut off mid-sweep anyway.
SWEEP_MAX = [33]
SWEEP_SKIP = ['02', '06', '24',   # consumed-and-waits, lone-record abort, no handler
              # 08 and 09 share the handler slot at [r2-0x4F78]; 08 after the
              # 0x07 step is REJECTED by that handler, which drives the session
              # state to 0xB and makes the client abort 31 ms later. Verified
              # 21:58 and 22:08. Incoming 0x21 is also unhandled, so it would do
              # the same -- never send it.
              # 0x24 aborted 20 ms after the client's 0x23 (22:24). In state 0x7
              # the no-handler arm drives the session to 0xB, so *every* type
              # without an arm is fatal here -- the v170 "harmless re-dispatch"
              # loop only happens in state 0xC, before the 0x07 step.
              '08', '09', '21', '24']
# (a plain list, not a one-element wrapper: `"06" in "02"` is a substring
#  test and silently skipped nothing -- found by running it, v171)
# Verified 21:51, 21:53, 21:58, 22:08 (four runs, real client, not the probe):
# 03, 04 and 05 are consumed without changing anything, then 07 makes the
# client answer `21 02 00 0E 01` ~30-57 ms later and moves the session state
# 0xC -> 0x7. That exact prefix is replayed first, so a sweep always reproduces
# the known-good start rather than betting that 07 works on its own -- 06
# aborted the client as a lone record, and 06/07 share one dispatch arm, so
# "lone record" is not a safe assumption for any of them.
#
# After the prefix comes the next reply to find: the answer to the client's
# 0x21. Medius numbers requests and answers as adjacent ids (0x20 is the
# client's own close message), so 0x22 -- which has its own handler slot at
# [r2-0x4F84] -- is tried first. The rest of the list is the remaining handled
# types in descending likelihood; the tail is untouched.
SWEEP_FIRST = ['reply_0x03.bin', 'reply_0x04.bin', 'reply_0x05.bin', 'reply_0x07.bin']
# After 0x22 the client sends type 0x23 = `01 1E "default_server_password_string"`
# (verified 22:13). That is a *login* message, not a certificate one, so the
# answer is a bare record with a short payload -- not the 740-byte certificate
# record that reply_0x25.bin still is (rejected by its handler at 22:13, state
# 0x7 -> 0xB). 0x24 is first because requests here pair with the adjacent id and
# the client's own 0x23 is the request; if 0x24 has no arm it just re-dispatches
# (the v170 loop) without aborting, so it is safe to try.
# Priority order after the verified prefix. The client only listens for about
# 3.0 s after our 0x1A (measured: 0x1A_s at 06.757 -> give-up 20 01 00 01 at
# 09.777, twice), and each candidate costs one gap, so the order decides what
# actually gets tried: the untried 0x0B..0x20 range comes first, the already
# answered 0x1B..0x1E records after it.
SWEEP_NEXT = [
              'reply_0x22.bin',
              'reply_0x25_g.bin',
              'reply_0x26_b.bin',
              'reply_0x2A_a.bin',
              'reply_0x28_s.bin',
              'reply_0x1A_s.bin',
              'reply_0x1B_b.bin',
              'reply_0x1C_b.bin',
              'reply_0x1D_b.bin',
              'reply_0x1E_b.bin',
             ] + ['reply_0x%02X_any.bin' % t for t in range(0x0B, 0x21)]

# Records that must never be sent: their handlers kill the connection or the
# title (each was observed aborting, not inferred).
SWEEP_SKIP_FILES = [
    'reply_0x2E_b.bin', 'reply_0x2C_b.bin', 'reply_0x14_b.bin', 'reply_0x13_b.bin',
    'reply_0x11_b.bin', 'reply_0x2A_s.bin', 'reply_0x19_s.bin', 'reply_0x1F_s.bin',
    'reply_0x26_c.bin', 'reply_0x26_d.bin', 'reply_0x26_e.bin', 'reply_0x26_f.bin',
    'reply_0x26_a.bin', 'reply_0x28.bin', 'reply_0x28_a.bin', 'reply_0x18.bin',
    'reply_0x18_a.bin', 'reply_0x18_s.bin', 'reply_0x1A.bin', 'reply_0x1A_a.bin',
    'reply_0x28_s.bin', 'reply_0x25.bin', 'reply_0x25_h.bin', 'reply_0x25_i.bin',
    'reply_0x25_j.bin', 'reply_0x25_k.bin', 'reply_0x25_a.bin',
    'reply_0x25_b.bin', 'reply_0x25_c.bin', 'reply_0x25_d.bin',
    'reply_0x25_e.bin', 'reply_0x25_f.bin',
]

# Extra exclusions learned at runtime, one record filename per line. The sweep
# loop appends to this so a fatal candidate is excluded without editing code
# (and without a stale hardcoded list drifting out of sync with the logs).
_SKIP_EXTRA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sweep_skip.txt')
if os.path.exists(_SKIP_EXTRA):
    with open(_SKIP_EXTRA, 'r', encoding='utf-8', errors='replace') as _f:
        for _line in _f:
            _t = _line.split('#', 1)[0].strip()
            if _t and _t not in SWEEP_SKIP_FILES:
                SWEEP_SKIP_FILES.append(_t)


def log(msg):
    stamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with LOCK:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"{stamp} {msg}\n")


def dump(tag, data, limit=1024):
    log(f"{tag} {len(data)} bytes")
    d = data[:limit]
    for off in range(0, len(d), 16):
        chunk = d[off:off + 16]
        hx = " ".join(f"{b:02X}" for b in chunk)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        log(f"  {tag[:3]} {off:04X}  {hx:<47}  {txt}")
    if len(data) > limit:
        log(f"  {tag[:3]} ... {len(data)} bytes total")


def describe(data):
    """Decode the record header the client sends first (see medius_wire.py).

    type(1) | msg_len(u16 LE) | fields(12) | der_len(u16 LE) | DER | 0000 0000
    """
    for line in w.describe(data, "  "):
        log(line)


def send_slow(conn, addr, port, out, chunk, delay):
    """Drip the reply out in small pieces.

    The client's record reader sits behind a virtual call, so its caller never
    appears in a stack sample taken while it waits -- it is only ever *inside*
    the read for a moment. Sending 32 bytes every 150 ms keeps it inside the
    read for seconds at a time, which is when `threads` on the debug console
    can see the frame above the dispatch."""
    log(f":{port}->{addr[1]}  dripping reply.bin ({len(out)} bytes, {chunk} at a time)")
    for off in range(0, len(out), chunk):
        piece = out[off:off + chunk]
        conn.sendall(piece)
        time.sleep(delay)
    log(f":{port}->{addr[1]}  drip complete")


def next_reply():
    """Which reply file to send for this connection.

    Default: logs/mp/reply.bin.  With --rotate: the reply_*.bin files in turn,
    one per connection, so a type sweep costs one click per candidate instead
    of a rebuild per candidate. The cycle wraps, so a lost connection does not
    silently skip a candidate."""
    if not ROTATE[0]:
        return REPLY
    files = sorted(glob.glob(os.path.join(LOGDIR, "reply_*.bin")))
    if not files:
        return REPLY
    path = files[ROT_IDX[0] % len(files)]
    log(f"  rotate: candidate {ROT_IDX[0] % len(files) + 1}/{len(files)} "
        f"= {os.path.basename(path)}")
    ROT_IDX[0] += 1
    return path


def sweep_candidates():
    """Every reply_*.bin whose type byte has not been ruled out yet, in name
    order. The type byte is the record's first byte (see medius_wire)."""
    paths = sorted(glob.glob(os.path.join(LOGDIR, "reply_*.bin")))
    by_name = {os.path.basename(p): p for p in paths}
    # both are plain lists (see the note on SWEEP_SKIP: indexing a list of
    # strings yields a string, and `x in "reply_0x03.bin"` is a substring test)
    out = [by_name[n] for n in SWEEP_FIRST if n in by_name]
    order = out + [by_name[n] for n in SWEEP_NEXT if n in by_name]
    rest = [p for p in paths if p not in order]
    for path in rest:
        if path in order:
            continue
        if os.path.basename(path) in SWEEP_SKIP_FILES:
            continue
        with open(path, "rb") as f:
            head = f.read(1)
        if not head:
            continue
        if f"{head[0]:02x}" in SWEEP_SKIP:
            continue
        order.append(path)
    # SWEEP_FIRST / SWEEP_NEXT are hand-written staging lists, so a record named
    # there used to ignore SWEEP_SKIP_FILES entirely and a fatal candidate that
    # had been staged (e.g. reply_0x05_b.bin) kept being sent and kept aborting
    # the run. Filter last, over everything, so no list can bypass an exclusion.
    order = [p for p in order if os.path.basename(p) not in SWEEP_SKIP_FILES]
    return order[:SWEEP_MAX[0]]


def digest_reply(data, mode):
    """Build the answer to a client digest record (see SWEEP_DUPLEX)."""
    t = data[0]
    body = data[3:]
    dig = body[-16:] if len(body) >= 16 else hashlib.sha1(b'').digest()[:16]
    if mode == 'hash':
        dig = hashlib.sha1(dig).digest()[:16]
    payload = b'\x01' + struct.pack('<I', 12744) + struct.pack('<I', 0) \
        + struct.pack('<I', 16) + dig
    return bytes([t]) + struct.pack('<H', len(payload)) + payload


def sweep(conn, addr, port):
    """Hand the client one candidate at a time on this one connection.

    The client sits in its reply window for up to 30 s, and it dispatches every
    record that arrives, so a second candidate can be tried without a new
    connection -- which is what makes a 30-type sweep a couple of clicks
    instead of 30. Every send is logged, so whichever candidate the client
    answers (or aborts on) is the last name in the log.

    Returns when the client sends anything, closes, or the list runs out.
    Everything the client sent is already dumped; the caller resumes the normal
    read loop."""
    last = None
    heard = 0
    cands = sweep_candidates()
    if SWEEP_ONLY[0]:
        names = [os.path.basename(p) for p in cands]
        cut = names.index('reply_0x1A_s.bin') + 1 if 'reply_0x1A_s.bin' in names else 0
        only = os.path.join(LOGDIR, SWEEP_ONLY[0])
        if os.path.exists(only):
            cands = cands[:cut] + [only]
            log(f"  SWEEP_ONLY: prefix + {SWEEP_ONLY[0]}")
        else:
            log(f"  SWEEP_ONLY: {only} not found")
    elif SWEEP_ONE[0] >= 0:
        names = [os.path.basename(p) for p in cands]
        try:
            cut = names.index('reply_0x1A_s.bin') + 1
        except ValueError:
            cut = 0
        post = cands[cut:]
        if SWEEP_ONE[0] < len(post):
            cands = cands[:cut] + [post[SWEEP_ONE[0]]]
            log(f"  single-candidate mode: index {SWEEP_ONE[0]} of "
                f"{len(post)} post-prefix records = {os.path.basename(post[SWEEP_ONE[0]])}")
        else:
            log(f"  single-candidate mode: index {SWEEP_ONE[0]} is past the end "
                f"({len(post)} post-prefix records) -- sending the prefix only")
            cands = cands[:cut]
    for path in cands:
        try:
            with open(path, "rb") as f:
                out = f.read()
        except OSError as e:
            log(f"  sweep: cannot read {os.path.basename(path)}: {e}")
            continue
        if not out:
            continue
        last = os.path.basename(path)
        log(f":{port}->{addr[1]}  sweep: sending {last} "
            f"({len(out)} B, type 0x{out[0]:02X})")
        try:
            conn.sendall(out)
        except OSError as e:
            log(f"  sweep: send failed on {last}: {e}")
            return
        conn.settimeout(SWEEP_GAP[0])
        try:
            data = conn.recv(65536)
        except socket.timeout:
            continue
        except OSError as e:
            log(f"  sweep: recv failed after {last}: {e}")
            return
        if not data:
            log(f"  sweep: client CLOSED after {last}")
            return
        dump(f":{port}<-{addr[1]}", data)
        # only answer a reply to the record we just sent: the prefix records
        # provoke unrelated client messages (0x07 -> 0x21) and answering those
        # with a digest record made the client drop the connection instantly.
        if SWEEP_DUPLEX[0] and len(data) >= 3 and data[0] == out[0]:
            nxt = digest_reply(data, SWEEP_DUPLEX[0])
            try:
                conn.sendall(nxt)
                log(f":{port}->{addr[1]}  duplex ({SWEEP_DUPLEX[0]}): "
                    f"answering type 0x{nxt[0]:02X} with {len(nxt)} B "
                    f"({nxt[:3].hex(' ')}) digest {nxt[-16:].hex()}")
            except OSError as e:
                log(f"  duplex send failed: {e}")
                return
            # give the client room to react to our answer
            conn.settimeout(2.0)
            try:
                more = conn.recv(65536)
            except (socket.timeout, OSError):
                more = b''
            if more:
                dump(f":{port}<-{addr[1]}", more)
                log(f"  duplex: client sent {len(more)} B after our digest "
                    f"answer ({more[:4].hex(' ')}))")
            else:
                log("  duplex: no reaction to our digest answer")
            after = SWEEP_AFTER[0]
            if after:
                p2 = after if os.path.isabs(after) else os.path.join(LOGDIR, after)
                try:
                    rec = open(p2, 'rb').read()
                    conn.sendall(rec)
                    log(f":{port}->{addr[1]}  after-digest: sending "
                        f"{os.path.basename(p2)} ({len(rec)} B, type 0x{rec[0]:02X})")
                    conn.settimeout(2.0)
                    try:
                        more2 = conn.recv(65536)
                    except (socket.timeout, OSError):
                        more2 = b''
                    if more2:
                        dump(f":{port}<-{addr[1]}", more2)
                        log(f"  after-digest: client sent {len(more2)} B "
                            f"({more2[:4].hex(' ')})")
                    else:
                        log("  after-digest: no reaction")
                except OSError as e:
                    log(f"  after-digest failed: {e}")
        if data[:1] == b'\x20' or data == b'\x20\x01\x00\x01':
            log(f"  sweep: client gave up right after {last} (20 01 00 01) -- "
                f"stopping: it is done listening, so nothing sent now can be "
                f"tested and would only be blamed for the drop")
            return
        heard += 1
        log(f"  sweep: client sent {len(data)} B after {last} "
            f"({data[:4].hex(' ')}) -- continuing, so the NEXT candidate that "
            f"provokes a send is the one to look at")
    if SWEEP_KEEPALIVE[0]:
        try:
            fname, gap, cnt = SWEEP_KEEPALIVE[0].split(':')
            rec = open(os.path.join(LOGDIR, fname), 'rb').read()
            gap = float(gap)
            for i in range(int(cnt)):
                conn.sendall(rec)
                log(f":{port}->{addr[1]}  keepalive {i+1}/{cnt}: {fname} "
                    f"({len(rec)} B, type 0x{rec[0]:02X})")
                conn.settimeout(gap)
                try:
                    more = conn.recv(65536)
                except (socket.timeout, OSError):
                    more = b''
                if more:
                    dump(f":{port}<-{addr[1]}", more)
                    log(f"  keepalive: client sent {len(more)} B ({more[:4].hex(' ')})")
                else:
                    log("  keepalive: no send from client this tick")
        except (ValueError, OSError) as e:
            log(f"  keepalive failed: {e}")
    log(f"  sweep: finished {last or 'the candidate list'}; "
        f"{heard} client send(s) during the sweep")


def paced_sweep(conn, addr, port):
    """Hold the session open with pings and test one candidate at a time."""
    names = [os.path.basename(p) for p in sweep_candidates()]
    cut = names.index('reply_0x1A_s.bin') + 1 if 'reply_0x1A_s.bin' in names else 0
    ping = open(os.path.join(LOGDIR, SWEEP_PACED[0]), 'rb').read()
    # v183: SWEEP_LIST_<port> overrides SWEEP_LIST for one listening port, so a
    # multi-server flow (universe :10071 -> auth :10073 -> lobby ...) can answer
    # each server's request with its own records.
    per_port = [x.strip() for x in os.environ.get(f'SWEEP_LIST_{port}', '').split(',') if x.strip()]
    lst = per_port or SWEEP_LIST
    cands = ([os.path.join(LOGDIR, x) for x in lst] if lst
             else sweep_candidates()[cut:])
    log(f"  paced sweep: prefix through 0x1A_s, then {len(cands)} candidates, "
        f"ping {SWEEP_PACED[0]} every {SWEEP_PACED_GAP[0]} s")
    hits = 0
    for path in cands:
        base = os.path.basename(path)
        rec = open(path, 'rb').read()
        try:
            conn.sendall(rec)
            log(f":{port}->{addr[1]}  paced: {base} ({len(rec)} B, type 0x{rec[0]:02X})")
            conn.settimeout(SWEEP_PACED_GAP[0])
            try:
                data = conn.recv(65536)
            except (socket.timeout, OSError):
                data = b''
            if data:
                dump(f":{port}<-{addr[1]}", data)
                if not data.startswith(b'\x1f'):
                    hits += 1
                    log(f"  paced: *** {base} drew a NON-PING send: "
                        f"{len(data)} B ({data[:8].hex(' ')})")
            conn.sendall(ping)
            conn.settimeout(SWEEP_PACED_GAP[0])
            try:
                pong = conn.recv(65536)
            except (socket.timeout, OSError):
                pong = b''
            if pong:
                dump(f":{port}<-{addr[1]}", pong)
            if pong and not pong.startswith(b'\x1f'):
                hits += 1
                log(f"  paced: *** after {base} the client sent {len(pong)} B "
                    f"({pong[:8].hex(' ')}) instead of a ping reply")
        except OSError as e:
            log(f"  paced: connection lost at {base}: {e}")
            return
    log(f"  paced sweep done: {len(cands)} candidates, {hits} non-ping reactions")


def respond_loop(conn, addr, port, pre=b''):
    """v184 responder: answer each client Medius request (RT 0x0B) by rule
    (medius_replies.RULES, MessageID echoed) and keep the session alive with
    the ping record, so the 3 s inactivity give-up never fires."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib
    import medius_replies
    importlib.reload(medius_replies)   # edit rules between runs without a restart
    ping = open(os.path.join(LOGDIR, SWEEP_PACED[0] or 'reply_0x1F_e.bin'), 'rb').read()
    gap = SWEEP_PACED_GAP[0] or 0.5
    buf = b''
    respond_loop._mtime = os.path.getmtime(medius_replies.__file__)
    # per-connection context handed to every builder (which port/peer, and a
    # place for builders to remember per-session things such as the player)
    conn_ctx = {'port': port, 'addr': addr, 'conn': conn}
    log(f"  respond: rule-based replies on :{port} ({len(medius_replies.RULES)} rules), "
        f"ping every {gap} s")
    # Requests that arrived during the RT prefix: only whole 0x0B records count
    # (the prefix replies are RT handshake records, not app messages).
    pending = [p for t, p in medius_replies.parse_records(pre)[0] if t == 0x0B]
    while True:
        if pending:
            data = bytes([0x0B]) + struct.pack('<H', len(pending[0])) + pending.pop(0)
        else:
            conn.settimeout(gap)
            try:
                data = conn.recv(65536)
            except socket.timeout:
                data = None
            except OSError as e:
                log(f"  respond: connection lost: {e}")
                return
        if data == b'':
            log("  respond: client closed")
            return
        if data is None:
            try:
                conn.sendall(ping)
            except OSError as e:
                log(f"  respond: ping failed: {e}")
                return
            continue
        dump(f":{port}<-{addr[1]}", data)
        # Lobby sessions stay connected for minutes; pick up rule edits
        # mid-connection instead of only at connect (v184).
        mt = os.path.getmtime(medius_replies.__file__)
        if mt != getattr(respond_loop, '_mtime', mt):
            try:
                importlib.reload(medius_replies)
                log(f"  respond: reloaded medius_replies ({len(medius_replies.RULES)} rules)")
            except Exception as e:
                log(f"  respond: reload FAILED, keeping old rules: {e!r}")
        respond_loop._mtime = mt
        recs, buf = medius_replies.parse_records(buf + data)
        for t, payload in recs:
            if t != 0x0B:
                continue
            try:
                desc, out = medius_replies.answer(payload, conn_ctx)
            except Exception as e:
                import traceback
                log(f"  respond: builder raised {e!r}\n{traceback.format_exc()}")
                continue
            log(f"  respond: *** {desc}")
            if out:
                try:
                    conn.sendall(out)
                except OSError as e:
                    log(f"  respond: send failed: {e}")
                    return
                log(f":{port}->{addr[1]}  respond: sent {len(out)} B "
                    f"(class {out[3]} id 0x{out[4]:02X})")


def handle(conn, addr, port):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # v185: small records, no Nagle delay
    log(f":{port} <- {addr[0]}:{addr[1]}  CONNECTED")
    conn.settimeout(1.0)
    first = True
    idle = 0.0
    try:
        while True:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                idle += 1.0
                if idle in (5.0, 15.0, 25.0):
                    log(f":{port} <- {addr[0]}:{addr[1]}  idle {idle:.0f} s")
                if idle > 45:
                    log(f":{port} <- {addr[0]}:{addr[1]}  idle limit")
                    break
                continue
            idle = 0.0
            if not data:
                break
            dump(f":{port}<-{addr[1]}", data)
            if first:
                first = False
                describe(data)
                if SWEEP[0] and SWEEP_PACED[0]:
                    # prefix only, then the paced loop takes over
                    names = [os.path.basename(x) for x in sweep_candidates()]
                    cut = names.index('reply_0x1A_s.bin') + 1
                    pre = b''
                    for path in sweep_candidates()[:cut]:
                        out = open(path, 'rb').read()
                        conn.sendall(out)
                        log(f":{port}->{addr[1]}  sweep: sending "
                            f"{os.path.basename(path)} ({len(out)} B, "
                            f"type 0x{out[0]:02X})")
                        conn.settimeout(SWEEP_GAP[0])
                        try:
                            got = conn.recv(65536)
                        except (socket.timeout, OSError):
                            got = b''
                        if got:
                            dump(f":{port}<-{addr[1]}", got)
                            pre += got
                    if os.environ.get('MEDIUS_RESPOND'):
                        respond_loop(conn, addr, port, pre)
                        break
                    paced_sweep(conn, addr, port)
                    conn.settimeout(1.0)
                    continue
                if SWEEP[0]:
                    sweep(conn, addr, port)
                    conn.settimeout(1.0)
                    continue
                path = next_reply()
                if path and os.path.exists(path):
                    with open(path, "rb") as f:
                        out = f.read()
                    if out:
                        log(f":{port}->{addr[1]}  sending {os.path.basename(path)} "
                            f"({len(out)} bytes)")
                        dump(f":{port}->{addr[1]}", out)
                        if DRIP[0] > 0:
                            send_slow(conn, addr, port, out, DRIP[0], DRIP[1])
                        else:
                            conn.sendall(out)
                else:
                    log(f":{port}->{addr[1]}  no reply -- staying quiet")
    except OSError as e:
        log(f":{port} <- {addr[0]}:{addr[1]}  error {e}")
    finally:
        log(f":{port} <- {addr[0]}:{addr[1]}  CLOSED")
        conn.close()


def listen(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    log(f"listening TCP :{port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, port), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default="10071,10072,10073,10074,10075,10076")
    ap.add_argument("--rotate", action="store_true",
                    help="send reply_*.bin in turn, one per connection (type sweep)")
    ap.add_argument("--drip", type=int, default=int(os.environ.get("MP_DRIP_CHUNK", "0")),
                    help="send the reply in chunks of this many bytes")
    ap.add_argument("--drip-delay", type=float, default=float(os.environ.get("MP_DRIP_DELAY", "0.15")))
    ap.add_argument("--sweep", action="store_true",
                    help="try every reply_*.bin on ONE connection, one per gap, "
                         "instead of one per connection")
    ap.add_argument("--sweep-gap", type=float, default=None,
                    help="seconds to wait for the client after each candidate")
    ap.add_argument("--sweep-max", type=int, default=33,
                    help="stop the sweep after this many candidates (the client's "
                         "reply window is 30 s; 0.6 s each)")
    ap.add_argument("--sweep-skip", default="02,06,24",
                    help="comma-separated type bytes already ruled out")
    args = ap.parse_args()
    DRIP[0] = args.drip
    ROTATE[0] = args.rotate
    DRIP[1] = args.drip_delay
    SWEEP[0] = args.sweep
    if args.sweep_gap is not None:
        SWEEP_GAP[0] = args.sweep_gap
    SWEEP_MAX[0] = args.sweep_max
    SWEEP_SKIP[:] = [x.strip().lower() for x in args.sweep_skip.split(",") if x.strip()]
    os.makedirs(LOGDIR, exist_ok=True)
    open(LOG, "w").close()
    log("medius v0 starting")
    for p in [int(x) for x in args.ports.split(",") if x.strip()]:
        threading.Thread(target=listen, args=(p,), daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
