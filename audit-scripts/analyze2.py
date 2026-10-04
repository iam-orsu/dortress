import re, struct

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\application1.exe"
data = open(P, 'rb').read()
n = len(data)
print("exe size", n)

def findall(pat):
    return [m.start() for m in re.finditer(re.escape(pat), data)]

for magic in (b'DUSBLK1', b'DLK3'):
    offs = findall(magic)
    print(f"\n{magic}: {len(offs)} occurrences at {offs}")

# Trailer interpretation
tail16 = data[-16:]
print("\nlast16:", tail16.hex())
magic8 = tail16[:8]
num8 = tail16[8:]
print("magic8:", magic8, "num8 LE:", struct.unpack('<q', num8)[0], "num8 BE:", struct.unpack('>q', num8)[0])

# Try treating num8 as offset
off = struct.unpack('<q', num8)[0]
if 0 <= off < n:
    print("bytes at offset", off, ":", data[off:off+64].hex())
    print("ascii:", data[off:off+64])

# reverse interpretation
magic8b = tail16[8:]
num8b = tail16[:8]
offb = struct.unpack('<q', num8b)[0]
print("alt magic:", magic8b, "alt offset LE:", offb)
if 0 <= offb < n:
    print("bytes at alt offset", offb, ":", data[offb:offb+32].hex())

# Go symbol-like strings
print("\n--- 'main.' symbols ---")
syms = sorted(set(re.findall(rb'main\.[A-Za-z0-9_.()*]+', data)))
for s in syms:
    print("  ", s.decode())
