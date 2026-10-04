import struct, zlib, os

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123"

def dump_png(path):
    data = open(path,'rb').read()
    print(f"=== PNG {path} ({len(data)} bytes) ===")
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    off = 8
    while off < len(data):
        ln = struct.unpack('>I', data[off:off+4])[0]
        typ = data[off+4:off+8].decode('latin1')
        chunk = data[off+8:off+8+ln]
        print(f"  chunk {typ} len={ln}")
        if typ == 'IHDR':
            w,h,bd,ct,comp,filt,inter = struct.unpack('>IIBBBBB', chunk)
            print(f"    width={w} height={h} bitdepth={bd} colortype={ct} interlace={inter}")
        if typ in ('tEXt','iTXt','zTXt'):
            print("    TEXT:", chunk[:400])
        off += 12 + ln

def dump_head(path, n=128):
    data = open(path,'rb').read()
    print(f"=== {path} ({len(data)} bytes) ===")
    print("  first", n, "bytes:", data[:n])

dump_png(os.path.join(P,'a.png'))
print()
data = open(os.path.join(P,'a.txt'),'rb').read()
print("=== a.txt size", len(data))
print("  first 64:", data[:64])
