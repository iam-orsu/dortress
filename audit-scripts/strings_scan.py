import re, sys

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\application1.exe"
data = open(P, 'rb').read()
print("exe size", len(data))

# Extract printable ascii strings >= 5
pat = re.compile(rb'[\x20-\x7e]{5,}')
strings = pat.findall(data)
print("ascii strings:", len(strings))

keywords = [b'ZEUSBGV', b'hello world hack me', b'DLK3', b'DUSBLK1', b'DORTRESS', b'dortress',
            b'96269', b'scifiinc', b'Sentinel', b'cipher', b'msbj', b'Fernet', b'fernet',
            b'scrypt', b'UNLOCK', b'unlock', b'pass.txt', b'a.txt', b'a.png']

seen = set()
for kw in keywords:
    hits = [s for s in strings if kw in s]
    uniq = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    print(f"\n### {kw.decode(errors='replace')} -> {len(hits)} hits, {len(uniq)} unique")
    for h in uniq[:40]:
        print("   ", h[:300].decode(errors='replace'))
