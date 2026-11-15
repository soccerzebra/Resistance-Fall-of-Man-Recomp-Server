"""Medius app-message replies, built per request (v184).

Wire: RT record 0x0A | u16 LE len | class u8 | id u8 | struct. The client's
requests arrive as RT 0x0B with the same inner layout; the reply is routed to
the pending request by its MessageID (21 bytes at the struct start), so every
builder echoes the request's MessageID. Plain u32 fields are little-endian;
ints inside raw blobs are big-endian.

RULES maps (class, id) of a client request to a builder(msgid, req_struct)
-> reply record. medius_server.py's responder mode (MEDIUS_RESPOND=1) uses it.
"""
import os
import struct
import time


def rec(cls, mid, struct_bytes):
    body = bytes([cls, mid]) + bytes(struct_bytes)
    return bytes([0x0A]) + struct.pack('<H', len(body)) + body


def _put(buf, off, data):
    buf[off:off + len(data)] = data


def _msgid(buf, msgid):
    _put(buf, 0, msgid[:21])


from mp_config import PUBLIC_HOST_B   # noqa: E402  (MP_PUBLIC_HOST, default 127.0.0.1)

SESSION_KEY = b'0123456789ABCDEF'
SVO_URL = b'http://' + PUBLIC_HOST_B + b':10080/'
LOBBY_PORT = 10073


def universe_info(msgid, req, port=LOBBY_PORT, dns=PUBLIC_HOST_B):
    """class 1 0x4D, answer to 0xC8 (universe lookup). 0x40C bytes."""
    s = bytearray(0x40C)
    _msgid(s, msgid)
    _put(s, 0x18, struct.pack('<I', 0))        # StatusCode
    _put(s, 0x1C, struct.pack('<I', 0x37C))    # InfoFilter
    _put(s, 0x20, struct.pack('>I', 1))        # UniverseID (blob: BE)
    _put(s, 0x24, b'TestUniverse')
    _put(s, 0xA4, dns)                         # DNS
    _put(s, 0x124, struct.pack('>i', port))    # Port (blob: BE)
    _put(s, 0x128, b'Local test universe')
    _put(s, 0x228, struct.pack('>i', 1))       # Status
    _put(s, 0x22C, struct.pack('>i', 0))       # UserCount
    _put(s, 0x230, struct.pack('>i', 256))     # MaxUsers
    _put(s, 0x33C, SVO_URL)                    # SvoURL: explicit port required
    s[0x3BC] = 1
    s[0x408] = 1                               # EndOfList
    return rec(0x01, 0x4D, s)


def session_begin(msgid, req):
    """class 1 0x04, answer to class 4 0x27 (session begin). 0x30 bytes."""
    s = bytearray(0x30)
    _msgid(s, msgid)
    _put(s, 0x18, struct.pack('<I', 0))
    _put(s, 0x1C, SESSION_KEY)
    return rec(0x01, 0x04, s)


def status_4_29(msgid, req):
    """class 4 0x29 generic status, answer to class 4 0x5A. 0x1C bytes."""
    s = bytearray(0x1C)
    _msgid(s, msgid)
    _put(s, 0x18, struct.pack('<I', 0))
    return rec(0x04, 0x29, s)


POLICY_TEXT = b'Welcome to the local test server.'


def get_policy(msgid, req):
    """class 1 0x48 GetPolicy response, answer to class 1 0x47 {MessageID[21],
    SessionKey[17], pad 2, u32 PolicyType @40}. 0x120 bytes. The client asks
    twice per login -- PolicyType 0 (usage) then 1 (privacy) -- and shows both
    texts, so only the usage policy carries the welcome line (v186: it was
    shown twice)."""
    ptype = struct.unpack_from('<I', req, 40)[0] if len(req) >= 44 else 0
    s = bytearray(0x120)
    _msgid(s, msgid)
    _put(s, 0x18, struct.pack('<i', 0))
    if ptype == 0:
        _put(s, 0x1C, POLICY_TEXT[:255])
    s[0x11C] = 1                               # EndOfList
    return rec(0x01, 0x48, s)


# --- announcements (v186) ------------------------------------------------------
# 1/0x4C (and 1/0x4B) {MessageID, SessionKey, pad 2, u32 AppID} is the
# announcements request (func_002FF294, ser func_00606C50 -> class 1 id 0x4C),
# not a universe lookup. Its answer is 1/0x4D records (0x40C, callback
# func_002FF77C / func_002FF4A4): MessageID | pad 3 | Status @0x18 |
# AnnouncementID @0x1C | Announcement[1000] @0x20 | u8 EndOfList @0x408.
# The game keeps up to 5 (newest IDs), the front end shows them under its
# "announcements" title (localized string 0x311). Text comes from
# announcements.txt: one announcement per block, blocks separated by a
# line holding only "---". Re-read on every request (edit it live).
ANNOUNCE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'announcements.txt')
ANNOUNCE_DEFAULT = [b'Welcome! This is a community server for Resistance: Fall of Man.']


def announcements():
    try:
        raw = open(ANNOUNCE_FILE, 'rb').read().decode('utf-8', 'replace').replace('\r\n', '\n')
    except OSError:
        return ANNOUNCE_DEFAULT
    out = []
    for block in raw.split('\n---\n'):
        lines = [l for l in block.split('\n') if not l.lstrip().startswith('#')]
        text = '\n'.join(lines).strip()
        if text:
            out.append(text.encode('ascii', 'replace')[:999])
    return out[:5] or ANNOUNCE_DEFAULT


ANNOUNCE_MAX = int(os.environ.get('MEDIUS_ANNOUNCE_MAX', '1'))


def get_announcements(msgid, req):
    items = announcements()[:ANNOUNCE_MAX]
    recs = []
    for i, text in enumerate(items):
        s = bytearray(0x40C)
        _msgid(s, msgid)
        _put(s, 0x18, struct.pack('<i', MEDIUS_SUCCESS))
        _put(s, 0x1C, struct.pack('<I', i + 1))   # AnnouncementID
        _put(s, 0x20, text)
        s[0x408] = 1 if i == len(items) - 1 else 0
        recs.append(rec(0x01, 0x4D, s))
    return b''.join(recs)


WORLD_PORT = 10074
NAT_PORT = 10070
ACCOUNT_ID = 1001


NET_TCP = 1             # NetConnectionTypeClientServerTCP
NET_TCP_AUX_UDP = 3     # NetConnectionTypeClientServerTCPAuxUDP
# The game server (DME) connection: TCP + the aux UDP channel for in-match
# traffic. DME_AUX_UDP=0 falls back to TCP only.
DME_CONN_TYPE = NET_TCP if os.environ.get('DME_AUX_UDP', '1') == '0' else NET_TCP_AUX_UDP


def net_connection_info(port=WORLD_PORT, host=PUBLIC_HOST_B, world_id=1, conn_type=NET_TCP):
    """NetConnectionInfo, 0x9C bytes (deser func_00655DE4):
    u32 Type @0 | NetAddressList @4 (2 x raw 0x18 blob {u32 type, char[16], u32 port},
    BE: raw) | u32 WorldID @0x34 | ServerKey 16 x u32 @0x38 | SessionKey[17] @0x78 |
    AccessKey[17] @0x89 | pad 2."""
    # Each NetAddress is read field by field (func_0065C6F4): u32 LE type,
    # char[16], u32 LE port -- little-endian, NOT a raw big-endian blob (v184).
    c = bytearray(0x9C)
    _put(c, 0x00, struct.pack('<I', conn_type))
    a = bytearray(0x18)
    _put(a, 0x00, struct.pack('<I', 1))                  # NetAddressTypeExternal
    _put(a, 0x04, host)
    _put(a, 0x14, struct.pack('<I', port))
    _put(c, 0x04, a)
    # Second entry: the NAT service address. The 0x59 handler (func_00615E84)
    # hands it to func_0064C384 -> func_00651B78, which accepts only type 3
    # (NATService, string) or 8 (binary); anything else sets RT error 2, and the
    # next pump step fires the connection-lost callback -> "Network connection
    # failed" (v184).
    n = bytearray(0x18)
    _put(n, 0x00, struct.pack('<I', 3))                  # NetAddressTypeNATService
    _put(n, 0x04, host)
    _put(n, 0x14, struct.pack('<I', NAT_PORT))
    _put(c, 0x1C, n)
    _put(c, 0x34, struct.pack('<I', world_id))           # WorldID
    _put(c, 0x78, SESSION_KEY)
    _put(c, 0x89, b'ACCESSKEY0123456')
    return c


def ticket_login(msgid, req):
    """class 4 0x59 TicketLogin response, answer to class 4 0x58 (v184).
    deser func_006140B8: MessageID[21] | pad 3 | u32 StatusCode @0x18 |
    u32 PasswordType @0x1C | AccountLoginResponse @0x20 (func_00613FC0, 0xC4):
    {MessageID[21], pad 3, StatusCode @+0x18, AccountID @+0x1C,
     AccountType @+0x20, WorldID @+0x24, NetConnectionInfo @+0x28}.
    On success the callback (func_002F54A4) stores the AccountID, copies the
    NetConnectionInfo into the lobby manager and sets lobby state 0xB
    (reconnect to the address in it), then starts SVO TicketLogin."""
    # Wire != struct here: the outer deserializer (func_006140B8) reads the
    # MessageID and then the two u32s with NO pad (no func_0065CFEC call), so on
    # the wire they sit at 21 and 25 and the sub-struct starts at 29. Padding
    # them to 0x18 (as in the in-memory struct) shifted every later field by 3
    # bytes; the NAT-address check then read garbage and raised RT error 0x19
    # ("Network connection failed") (v184). The sub-struct keeps its pad 3.
    s = bytearray(msgid[:21].ljust(21, b'\0'))
    s += struct.pack('<i', 0)                 # StatusCode
    s += struct.pack('<I', 0)                 # PasswordType
    sub = bytearray(0xC4)
    _msgid(sub, msgid)
    _put(sub, 0x18, struct.pack('<i', 0))
    _put(sub, 0x1C, struct.pack('<I', ACCOUNT_ID))
    _put(sub, 0x20, struct.pack('<I', 0))     # AccountType: regular
    _put(sub, 0x24, struct.pack('<I', 1))     # WorldID
    _put(sub, 0x28, net_connection_info())
    s += sub
    return rec(0x04, 0x59, s)


# --- MLS (lobby, :10074) requests after "Connect to MLS" (v184) -------------
# Status values from the game's own name table at 0x100FFA78:
# MediusSuccess 0, MediusNoResult 1 (the "empty list" answer),
# MediusTransactionTimedOut -931.
MEDIUS_SUCCESS = 0
MEDIUS_NO_RESULT = 1


def _hdr(msgid):
    """MessageID[21] + pad 3 (deserializer calls func_0065CFEC(3))."""
    return bytearray(msgid[:21].ljust(21, b'\0')) + b'\0' * 3


def status_4_2B(msgid, req):
    """class 4 0x2B, answer to 4/0x2A {MessageID}. deser func_0061E2D8:
    MessageID | pad 3 | u32 @0x18 (status) | u32 @0x1C | u32 @0x20."""
    s = _hdr(msgid) + struct.pack('<iII', MEDIUS_SUCCESS, 0, 0)
    return rec(0x04, 0x2B, s)


def get_my_clans(msgid, req):
    """class 1 0x7D GetMyClans response, answer to 1/0x7C {MessageID,
    SessionKey[17], pad 2, u32 Start, u32 PageSize}. deser func_0061DF58:
    MessageID | pad 3 | Status | ClanID | AppID | ClanName[32] |
    LeaderAccountID | LeaderName[32] | Stats[256] | ClanStatus | u8 EndOfList |
    pad 3. No clans: MediusNoResult with EndOfList (the game logged
    "MediusGetMyClans failed." on the 8 s timeout)."""
    s = _hdr(msgid) + struct.pack('<iiI', MEDIUS_NO_RESULT, -1, 0)
    s += b'\0' * 32 + struct.pack('<i', -1) + b'\0' * 32 + b'\0' * 256
    s += struct.pack('<I', 0) + b'\x01' + b'\0' * 3
    return rec(0x01, 0x7D, s)


def list_1_C1(msgid, req):
    """class 1 0xC1, answer to 1/0xC0 {MessageID, SessionKey[17]}. deser
    func_0061CD88: MessageID | pad 3 | Status | u32 | char[32] | u32 |
    u8 EndOfList | pad 3. Empty list: MediusNoResult + EndOfList."""
    s = _hdr(msgid) + struct.pack('<iI', MEDIUS_NO_RESULT, 0) + b'\0' * 32
    s += struct.pack('<I', 0) + b'\x01' + b'\0' * 3
    return rec(0x01, 0xC1, s)


def reply_4_5E(msgid, req):
    """class 4 0x5E, answer to 4/0x5D {MessageID, SessionKey[17]} (resent
    every ~8 s while unanswered). deser func_0061561C, packed, no pad:
    MessageID[21] | u32 @0x18 | u8 @0x1C | u32 @0x18 again | u32 @0x20,
    0x24 | u32 sizes @0x28, 0x2C, 0x30 | then three blobs of those sizes.
    All sizes 0 -> no blobs."""
    s = bytearray(msgid[:21].ljust(21, b'\0'))
    s += struct.pack('<i', MEDIUS_SUCCESS) + b'\x01'
    s += struct.pack('<i', MEDIUS_SUCCESS)
    s += struct.pack('<IIIII', 0, 0, 0, 0, 0)
    return rec(0x04, 0x5E, s)


def list_1_65(msgid, req):
    """class 1 0x65, answer to 1/0x64 {MessageID, SessionKey[17], pad 2,
    u32 Start, u32 PageSize} (resent every ~10 s while unanswered; likely
    clan invitations). deser func_0061B398: MessageID | pad 3 | Status |
    u32 @0x1C | u32 @0x20 | u32 @0x24 | char[200] @0x28 | u32 @0xF0 |
    char[32] @0xF4 | u8 EndOfList | pad 3. Empty: NoResult + EndOfList."""
    s = _hdr(msgid) + struct.pack('<iIII', MEDIUS_NO_RESULT, 0, 0, 0)
    s += b'\0' * 200 + struct.pack('<I', 0) + b'\0' * 32 + b'\x01' + b'\0' * 3
    return rec(0x01, 0x65, s)


APP_ID = 0x4ECE            # from the client's 1/0x4C request
PLAYER_NAME = b'TestPlayer'
# Account stats blob (256 B) returned with the player info. All zero for now;
# the game's "Could not retrieve account stats!" fired when 0x31 had no reply.
# data/account_stats.bin, if present, replaces it (no restart needed).
from mp_config import DATA_DIR   # noqa: E402
STATS_FILE = os.path.join(DATA_DIR, 'account_stats.bin')


def player_info(msgid, req):
    """class 1 0x32 GetPlayerInfo response, answer to 1/0x31 {MessageID,
    SessionKey[17], pad 2, u32 AccountID}. deser func_0061F05C: MessageID |
    pad 3 | Status @0x18 | AccountName[32] @0x1C | AppID @0x3C |
    PlayerStatus @0x40 | ConnectionClass @0x44 | Stats[256] @0x48."""
    import os
    stats = open(STATS_FILE, 'rb').read()[:256] if os.path.exists(STATS_FILE) else b''
    s = _hdr(msgid) + struct.pack('<i', MEDIUS_SUCCESS)
    s += PLAYER_NAME.ljust(32, b'\0')
    s += struct.pack('<IiI', APP_ID, 1, 0)     # PlayerStatus 1, ConnectionClass 0
    s += stats.ljust(256, b'\0')
    return rec(0x01, 0x32, s)


def update_stats(msgid, req):
    """class 1 0x12 AccountUpdateStats response, answer to 1/0x11 {MessageID[21],
    SessionKey[17], Stats[256] @0x26} (packed, no pad; ser func_0061A3D4).
    The stats are saved to STATS_FILE so the next GetPlayerInfo (0x32) returns
    what the game last stored. deser func_0062004C: MessageID | pad 3 | Status."""
    stats = req[0x26:0x26 + 256]
    if len(stats) == 256:
        with open(STATS_FILE, 'wb') as f:
            f.write(stats)
    return rec(0x01, 0x12, _hdr(msgid) + struct.pack('<i', MEDIUS_SUCCESS))


def list_1_3E(msgid, req):
    """class 1 0x3E, answer to 1/0x3D {MessageID, SessionKey[17]}. deser
    func_0061CC60, same layout as 0xC1: MessageID | pad 3 | Status | u32 |
    char[32] | u32 | u8 EndOfList | pad 3. Empty: NoResult + EndOfList."""
    s = _hdr(msgid) + struct.pack('<iI', MEDIUS_NO_RESULT, 0) + b'\0' * 32
    s += struct.pack('<I', 0) + b'\x01' + b'\0' * 3
    return rec(0x01, 0x3E, s)


# --- custom games: filters and the game list (v184) ---------------------------
import medius_state as S      # not reloaded: games survive rule edits


def _note(msg):
    """extra detail line in data/medius_notes.log"""
    import os, time
    p = os.path.join(os.path.dirname(STATS_FILE), 'medius_notes.log')
    with open(p, 'a', encoding='utf-8') as f:
        f.write(time.strftime('%H:%M:%S ') + msg + '\n')


def set_filter(msgid, req):
    """class 4 0x34 SetGameListFilter response, answer to 4/0x33 {MessageID |
    pad 3 | FilterField @0x18 | Mask @0x1C | ComparisonOperator @0x20 |
    BaselineValue @0x24}. deser func_00621B44: MessageID | pad 3 | Status |
    FilterID. Filters are accepted and ignored: the list returns every game."""
    _note('SetGameListFilter field %d mask 0x%X op %d baseline %d' % struct.unpack_from('<IIiI', req, 24))
    with S.LOCK:
        fid = S.NEXT_FILTER[0]; S.NEXT_FILTER[0] += 1
    return rec(0x04, 0x34, _hdr(msgid) + struct.pack('<iI', MEDIUS_SUCCESS, fid))


def game_record(msgid, g, eol):
    """one class 4 0x38 GameList response record (deser func_006228AC):
    MessageID | pad 3 | Status | WorldID | u16 PlayerCount | u16 MinPlayers |
    u16 MaxPlayers | pad 2 | 14 x u32 (GameLevel, PlayerSkillLevel, RulesSet,
    GenericField1..8, WorldSecurityLevel, WorldStatus, GameHostType) |
    GameName[64] | GameStats[256] | u8 EndOfList | pad 3."""
    s = _hdr(msgid) + struct.pack('<iI', MEDIUS_SUCCESS, g['world_id'])
    s += struct.pack('<HHH', player_count(g), g['min_players'], g['max_players']) + b'\0\0'
    s += struct.pack('<14I', *g['fields'])
    s += g['name'][:63].ljust(64, b'\0') + g['stats'][:256].ljust(256, b'\0')
    s += bytes([1 if eol else 0]) + b'\0' * 3
    return rec(0x04, 0x38, s)


def clear_filter(msgid, req):
    """class 4 0x32, answer to 4/0x31 {MessageID | pad 3 | u32 FilterID}
    ("Error clearing game list filter 6!" on timeout). deser func_0062158C:
    MessageID | pad 3 | Status | FilterID | FilterField | Mask | Op |
    Baseline | u8 EndOfList | pad 3 (paired by the table's id+1 rule)."""
    fid = struct.unpack_from('<I', req, 24)[0]
    _note(f'ClearGameListFilter {fid}')
    s = _hdr(msgid) + struct.pack('<iIIIiI', MEDIUS_SUCCESS, fid, 0, 0, 0, 0) + b'\x01' + b'\0' * 3
    return rec(0x04, 0x32, s)


# A fixed test game, so Search has something to show before anyone hosts.
# fields: GameLevel, PlayerSkillLevel, RulesSet, GenericField1..8,
# WorldSecurityLevel, WorldStatus (1 staging / 2 active), GameHostType.
# GameStats is a binary block the host fills in; the client's list code
# (func_0030183C) copies [0..0x91) and reads fields at 0x98..0xA4. Its filter
# (func_0030141C) drops a game unless the u32 at 0x98 (big-endian, raw) equals
# the client's own build/content number (func_00288770 -> [0x103C8768] =
# 0x50DE9 on this build), the player count is non-zero, and the game type byte
# at 0xA2 matches the Game Type filter (0 passes "ANY").
GAME_VERSION = 0x50DE9


def game_stats(version=GAME_VERSION, map_byte=0, type_byte=0):
    s = bytearray(256)
    s[0x98:0x9C] = struct.pack('>I', version)
    s[0x9E] = map_byte
    s[0xA2] = type_byte
    return bytes(s)


TEST_GAMES = [
    dict(world_id=7, name=b'Local Test Game', stats=game_stats(), min_players=1, max_players=8,
         players=['Host'], fields=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
] if os.environ.get('MEDIUS_TEST_GAME', '0') == '1' else []
# v185: the fixed game is off by default -- it has no real map/mode, and a
# match started from it hangs at the level transition. Players host instead
# (CreateGame below); MEDIUS_TEST_GAME=1 brings it back for list tests.


GAME_TTL = 60.0   # s without a WorldReport (hosts send one every ~15 s) -> gone


def all_games():
    """Live games: hosted ones whose host has reported recently. A game whose
    create never completed, or whose host left, has no WorldReport / stops
    reporting and drops out of the list (and is forgotten)."""
    now = time.time()
    with S.LOCK:
        for wid in [w for w, g in S.GAMES.items()
                    if now - g.get('last_report', g.get('created', now)) > GAME_TTL]:
            del S.GAMES[wid]
        live = [g for g in S.GAMES.values() if g.get('reported')]
    return live + TEST_GAMES


def player_count(g):
    return g.get('count') or len(g['players'])


def find_game(world_id):
    for g in all_games():
        if g['world_id'] == world_id:
            return g
    return None


def _peer():
    a = CTX.get('addr')
    return f'{a[0]}:{a[1]}' if a else '?'


def create_game(msgid, req):
    """CreateGame 4/0x2F (ser func_0061B88C), packed: MessageID[21] |
    SessionKey[17] | pad 2 | u32 @40 (0) | MinPlayers @44 | MaxPlayers @48 |
    GameLevel @52 | GameName[64] @56 | GamePassword[32] @120 |
    SpectatorPassword[32] @152 | PlayerSkillLevel, RulesSet, GenericField1..8,
    GameHostType (4), WorldSecurityLevel @184..228. No GameStats: the host
    publishes those (map, mode...) in its WorldReport once it is in the DME.
    Answer: Status @0x18 | WorldID @0x1C (the callback func_00305200 reads
    exactly those, then joins that world). See CREATE_REPLY_IDS."""
    _, min_p, max_p, level = struct.unpack_from('<4I', req, 40)
    name = req[56:120].split(b'\0')[0] or b'Game'
    f12 = struct.unpack_from('<12I', req, 184)
    wid = S.new_world_id()
    fields = [level, f12[0], f12[1], *f12[2:10], f12[11], 1, f12[10]]
    with S.LOCK:
        S.GAMES[wid] = dict(world_id=wid, name=name, stats=game_stats(), min_players=min_p or 1,
                            max_players=max_p or 8, players=[_peer()], fields=fields, count=1,
                            created=time.time())
    _note(f'CreateGame "{name.decode(errors="replace")}" min {min_p} max {max_p} '
          f'hostType {f12[10]} -> world {wid}')
    body = _hdr(msgid) + struct.pack('<iI', MEDIUS_SUCCESS, wid)
    return b''.join(rec(0x04, i, body) for i in CREATE_REPLY_IDS)


# Replies are paired with the pending request by MessageID alone, so only the
# first one sent counts -- and each type's handler passes the status from its
# own offset to the dispatcher: 4/0x49 (func_006198FC) takes it from +0x1C, so
# the callback saw the world id as the status ("Create game failed"). 4/0x4F
# (func_00616384) takes it from +0x18, matching Status @0x18 | WorldID @0x1C.
CREATE_REPLY_IDS = (0x4F,)


def world_report(msgid, req):
    """WorldReport 4/0x30 (ser func_00620634), one-way, sent by the host:
    u32 WorldID | u32 PlayerCount | GameName[64] @8 | GameStats[256] @72 |
    MinPlayers, MaxPlayers, GameLevel, PlayerSkillLevel, RulesSet,
    GenericField1..8, WorldStatus @328..380. This is where the map / mode the
    host chose reach the lobby (GameStats), so store it for GameList/GameInfo."""
    wid, count = struct.unpack_from('<II', req, 0)
    tail = struct.unpack_from('<14I', req, 328)
    with S.LOCK:
        g = S.GAMES.get(wid)
        if g is None:
            return None
        first = g.get('reported') is None
        g.update(name=req[8:72].split(b'\0')[0] or g['name'], stats=bytes(req[72:328]), count=count,
                 min_players=tail[0] or g['min_players'], max_players=tail[1] or g['max_players'],
                 reported=True, last_report=time.time())
        g['fields'] = [tail[2], tail[3], tail[4], *tail[5:13], g['fields'][11], tail[13], g['fields'][13]]
    if first:
        _note(f'WorldReport world {wid}: players {count} status {tail[13]} '
              f'stats[0x98:0xA6] {req[72 + 0x98:72 + 0xA6].hex()}')
    return None


def game_info(msgid, req):
    """class 4 0x36 GameInfo response, answer to 4/0x35 {MessageID,
    SessionKey[17], pad 2, u32 WorldID @wire 40}. deser func_0061C260:
    MessageID | pad 3 | Status @0x18 | AppID | MinPlayers | MaxPlayers |
    GameLevel | PlayerSkillLevel | PlayerCount @0x30 | GameStats[256] @0x34 |
    GameName[64] @0x134 | RulesSet @0x174 | GenericField1..8 @0x178 |
    WorldStatus @0x198 | GameHostType @0x19C."""
    wid = struct.unpack_from('<I', req, 40)[0]
    g = find_game(wid)
    _note(f'GameInfo world {wid}: {"found" if g else "NOT FOUND"}')
    if not g:
        s = _hdr(msgid) + struct.pack('<i', -977) + b'\0' * (416 - 28)   # MediusGameNotFound
        return rec(0x04, 0x36, s)
    f = g['fields']   # GameLevel, SkillLevel, RulesSet, G1..G8, Security, WorldStatus, HostType
    s = _hdr(msgid) + struct.pack('<iIIIIII', MEDIUS_SUCCESS, APP_ID, g['min_players'], g['max_players'],
                                  f[0], f[1], player_count(g))
    s += g['stats'][:256].ljust(256, b'\0') + g['name'][:63].ljust(64, b'\0')
    s += struct.pack('<I', f[2]) + struct.pack('<8I', *f[3:11]) + struct.pack('<II', f[12], f[13])
    return rec(0x04, 0x36, s)


def generic_5B(msgid, req):
    """class 4 0x5C, answer to 4/0x5B. Request (ser func_00615324), packed:
    MessageID[21] | SessionKey[17] | u32 A | u32 B | u32 len | data[len]; on a
    join it carries A=1 B=0 len 9 data 03 00000007 00050DE9 (type 3, world 7,
    build). Reply (deser func_006153E4), packed: MessageID[21] | u32 @0x18 |
    u32 @0x1C | u32 len @0x20 | data[len]. Semantics unknown yet: answer
    status 0, echo A, no data."""
    a, b, n = struct.unpack_from('<III', req, 38)
    data = req[50:50 + n]
    _note(f'0x5B A={a} B={b} len={n} data={data.hex()}')
    s = bytearray(msgid[:21].ljust(21, b'\0')) + struct.pack('<iII', MEDIUS_SUCCESS, a, 0)
    return rec(0x04, 0x5C, s)


DME_PORT = 10079     # dme/dme_server.py
JOIN_REPLY = 0x72    # candidate ids with Status|u32|NetConnectionInfo: 1/0x24, 4/0x68, 4/0x72


def join_game(msgid, req):
    """JoinGame (4/0x5B) answer. The game's JoinGame callback (func_00304678,
    "Successfully joined a game, Hurray!") reads Status @0x18, a u32 @0x1C and
    copies the 0x9C-byte NetConnectionInfo @0x20 -- the DME server to connect
    to. 4/0x72 (deser: MessageID | u32 | u32 | NetConnectionInfo, packed) is
    the packed-style match for the packed 0x5B request."""
    # The JoinGame REQUEST is 1/0xF3 (ser func_0061E99C): MessageID |
    # SessionKey | pad 2 | u32 WorldID @wire 40 | u32 JoinType @44 |
    # GamePassword[32] @48 | u32 GameHostType @80 | key blob. (4/0x5B, sent
    # first, is the GameEntryArbiter binary message to the host account.)
    world, jtype = struct.unpack_from('<II', req, 40)
    host_type = struct.unpack_from('<I', req, 80)[0] if len(req) >= 84 else 0
    _note(f'JoinGame world={world} joinType={jtype} hostType={host_type}')
    with S.LOCK:
        g = S.GAMES.get(world)
        if g is not None and _peer() not in g['players']:
            g['players'].append(_peer())
            if not g.get('reported'):
                g['count'] = len(g['players'])
    nci = net_connection_info(port=DME_PORT, world_id=world, conn_type=DME_CONN_TYPE)
    # Probe all three NetConnectionInfo-carrying replies at once; the client
    # completes the op with whichever one is the JoinGame response.
    pad = _hdr(msgid) + struct.pack('<iI', MEDIUS_SUCCESS, host_type) + nci
    packed = bytearray(msgid[:21].ljust(21, b'\0')) + struct.pack('<iI', MEDIUS_SUCCESS, host_type) + nci
    return rec(0x01, 0x24, pad) + rec(0x04, 0x68, pad) + rec(0x04, 0x72, packed)


def game_list(msgid, req):
    """class 4 0x38 records, answer to 4/0x37 {MessageID | pad 1 | u16 PageID |
    u16 PageSize}: one record per game, EndOfList on the last; no games ->
    a single NoResult record with EndOfList."""
    page, size = struct.unpack_from('<HH', req, 22)
    _note(f'GameList page {page} size {size} raw {req[21:26].hex()}')
    games = all_games()
    # The client fires pages 1..20 (size 100) at once; pages are 1-based.
    games = games[(page - 1) * size:page * size] if page >= 1 else games[:size]
    if not games:
        s = _hdr(msgid) + struct.pack('<iI', MEDIUS_NO_RESULT, 0) + b'\0' * 8
        s += b'\0' * (14 * 4) + b'\0' * 64 + b'\0' * 256 + b'\x01' + b'\0' * 3
        return rec(0x04, 0x38, s)
    return b''.join(game_record(msgid, g, i == len(games) - 1) for i, g in enumerate(games))


def session_end(msgid, req):
    """class 1 0x06 SessionEnd response, answer to 1/0x05. deser
    func_0061FC60: MessageID | pad 3 | Status."""
    return rec(0x01, 0x06, _hdr(msgid) + struct.pack('<i', MEDIUS_SUCCESS))


RULES = {
    (0x04, 0x2A): ('4/0x2A -> 4/0x2B status', status_4_2B),
    (0x01, 0x7C): ('GetMyClans -> 1/0x7D NoResult', get_my_clans),
    (0x01, 0xC0): ('1/0xC0 -> 1/0xC1 empty list', list_1_C1),
    (0x04, 0x5D): ('4/0x5D -> 4/0x5E', reply_4_5E),
    (0x01, 0x05): ('SessionEnd -> 1/0x06', session_end),
    (0x01, 0x64): ('1/0x64 -> 1/0x65 empty list', list_1_65),
    (0x01, 0x31): ('GetPlayerInfo -> 1/0x32', player_info),
    (0x01, 0x11): ('AccountUpdateStats -> 1/0x12 (stats saved)', update_stats),
    (0x01, 0x3D): ('1/0x3D -> 1/0x3E empty list', list_1_3E),
    (0x04, 0x33): ('SetGameListFilter -> 4/0x34', set_filter),
    (0x04, 0x37): ('GameList -> 4/0x38', game_list),
    (0x04, 0x31): ('ClearGameListFilter -> 4/0x32', clear_filter),
    (0x04, 0x35): ('GameInfo -> 4/0x36', game_info),
    # 4/0x5B is NOT answered: a 0x5C with status 0 / A echoed made the client
    # end its session at once (v184) -- likely a server->client command, not a
    # reply. Logged only.
    (0x04, 0x5B): ('arbiter binary msg to host: logged, no reply', lambda m, r: (generic_5B(m, r), None)[1]),
    (0x01, 0xF3): ('JoinGame -> NetConnectionInfo candidates', join_game),
    (0x04, 0x2F): ('CreateGame -> Status|WorldID candidates', create_game),
    # 4/0x30 WorldReport and 1/0x01 PlayerReport are one-way (no handler).
    (0x04, 0x30): ('WorldReport (one-way, stored)', world_report),
    (0x01, 0x01): ('PlayerReport (one-way, no reply)', lambda m, r: None),
    # 1/0x49 {SessionKey[17], pad 3, u32 state} is UpdateClientState: one-way,
    # no MessageID, no reply.
    (0x01, 0x49): ('UpdateClientState (one-way, no reply)', lambda m, r: None),
    (0x04, 0x58): ('TicketLogin -> 4/0x59', ticket_login),
    (0x01, 0xC8): ('universe lookup -> 0x4D', universe_info),
    (0x04, 0x27): ('session begin -> 1/0x04', session_begin),
    (0x04, 0x5A): ('0x5A -> 4/0x29 status', status_4_29),
    (0x01, 0x47): ('GetPolicy -> 1/0x48', get_policy),
    # 0x4C {MessageID, SessionKey, pad, u32 AppID (0x4ECE)}, sent after both
    # policies, is the announcements request (v186; it was answered with
    # universe info, which the game read as one empty announcement). 0x4D is
    # also the universe-info reply to 0xC8: same record type, per-request layout.
    (0x01, 0x4C): ('GetAnnouncements -> 1/0x4D records', get_announcements),
    (0x01, 0x4B): ('GetAllAnnouncements -> 1/0x4D records', get_announcements),
}


def parse_records(buf):
    """-> ([(type, payload)], leftover bytes)"""
    out = []
    i = 0
    while len(buf) - i >= 3:
        t = buf[i]
        n = struct.unpack_from('<H', buf, i + 1)[0]
        if len(buf) - i - 3 < n:
            break
        out.append((t, bytes(buf[i + 3:i + 3 + n])))
        i += 3 + n
    return out, bytes(buf[i:])


CTX = {}     # the current connection's context (set by answer for builders)


def answer(payload, ctx=None):
    """payload of a client 0x0B record -> (description, reply record or None)"""
    global CTX
    CTX = ctx if ctx is not None else {}
    if len(payload) < 2:
        return ('short app record', None)
    cls, mid = payload[0], payload[1]
    st = payload[2:]
    msgid = st[:21].split(b'\0')[0]
    rule = RULES.get((cls, mid))
    if not rule:
        return (f'UNHANDLED class {cls} id 0x{mid:02X} msgid {msgid!r}', None)
    desc, fn = rule
    return (f'class {cls} id 0x{mid:02X} msgid {msgid!r}: {desc}', fn(msgid, st))
