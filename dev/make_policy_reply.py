"""Medius class 1 0x48 = GetPolicy response, the answer to class 1 0x47 (v184).

The client sends 0x47 {MessageID[21], SessionKey[17], pad 2, u32 PolicyType}
right after SVO's URL_List page completes online init, and gives it 8 s
(func_002FF020 -> func_001BDD68, timeout 0x1F40). The 0x48 deserializer
(func_0061E1F8) reads:
    MessageID[21] | pad 3 | u32 StatusCode (LE) @0x18 | Policy[256] @0x1C |
    u8 EndOfList @0x11C | pad 3                        -> 0x120 bytes
EndOfList = 1 so the router (func_006082C4) retires the request.
"""
import os, struct, sys

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logs', 'mp')


def policy_reply(msgid=b'4', status=0, text=b'Welcome to the local test server.', eol=1):
    s = bytearray(0x120)
    s[0:len(msgid)] = msgid
    s[0x18:0x1C] = struct.pack('<i', status)
    s[0x1C:0x1C + len(text)] = text[:255]
    s[0x11C] = eol
    body = bytes([0x01, 0x48]) + bytes(s)
    return bytes([0x0A]) + struct.pack('<H', len(body)) + body


if __name__ == '__main__':
    msgid = (sys.argv[1] if len(sys.argv) > 1 else '4').encode()
    b = policy_reply(msgid)
    name = f'reply_0x0A_48_policy{msgid.decode()}.bin'
    open(os.path.join(OUT, name), 'wb').write(b)
    print(name, len(b))
