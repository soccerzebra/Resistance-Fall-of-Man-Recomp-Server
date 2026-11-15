import struct, os, sys
out = r'G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling\logs\mp'
def status_reply(cls, mid, msgid, status=0, name=None):
    s = bytearray(0x1C); s[0:len(msgid)] = msgid.encode(); s[0x18:0x1C] = struct.pack('<I', status)
    body = bytes([cls, mid]) + bytes(s)
    b = bytes([0x0A]) + struct.pack('<H', len(body)) + body
    open(os.path.join(out, name), 'wb').write(b); print(name, len(b))
status_reply(4, 0x29, '3', 0, 'reply_0x0A_4_29_status3.bin')
