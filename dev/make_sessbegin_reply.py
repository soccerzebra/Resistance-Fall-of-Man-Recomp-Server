import struct, os
out = r'G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling\logs\mp'
def app(cls, mid, struct_bytes):
    body = bytes([cls, mid]) + struct_bytes
    return bytes([0x0A]) + struct.pack('<H', len(body)) + body
# class 1 id 0x04: SessionBeginResponse {MessageID[21], pad3, Status u32 LE, SessionKey[17], pad3}
s = bytearray(0x30)
s[0:1] = b'2'
s[0x18:0x1C] = struct.pack('<I', 0)
s[0x1C:0x1C+16] = b'0123456789ABCDEF'
b = app(0x01, 0x04, bytes(s))
open(os.path.join(out, 'reply_0x0A_04_sessbegin.bin'), 'wb').write(b)
print(len(b), b.hex())
