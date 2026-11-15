import struct, os
out = r'G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling\logs\mp'
def put(buf, off, data): buf[off:off+len(data)] = data
def u4d(port, eol=1, tail=1, dns='127.0.0.1', svo='http://127.0.0.1:10080/'):
    s = bytearray(0x40C)
    put(s, 0x00, b'1')
    put(s, 0x18, struct.pack('<I', 0))        # StatusCode = success
    put(s, 0x1C, struct.pack('<I', 0x37C))    # InfoFilter (echo of request)
    put(s, 0x20, struct.pack('>I', 1))        # UniverseID (raw blob: big-endian)
    put(s, 0x24, b'TestUniverse')             # UniverseName[128]
    put(s, 0xA4, dns.encode())                # DNS[128]
    put(s, 0x124, struct.pack('>i', port))    # Port
    put(s, 0x128, b'Local test universe')     # Description[256]
    put(s, 0x228, struct.pack('>i', 1))       # Status
    put(s, 0x22C, struct.pack('>i', 0))       # UserCount
    put(s, 0x230, struct.pack('>i', 256))     # MaxUsers
    # SvoURL[128]. The port must be explicit: SVO's URL parser leaves the u16
    # port (URL object +0x90) at 0 when it is omitted -- no http default of 80 --
    # and the HTTP provider's connect (func_006AFFBC) refuses port 0 (v184).
    put(s, 0x33C, svo.encode())
    s[0x3BC] = eol
    s[0x408] = tail
    body = bytes([0x01, 0x4D]) + bytes(s)
    return bytes([0x0A]) + struct.pack('<H', len(body)) + body
b = u4d(10073); open(os.path.join(out, 'reply_0x0A_4D_univ.bin'), 'wb').write(b); print(len(b), b[:6].hex())

