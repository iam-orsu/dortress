import hashlib, hmac
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2

A = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\a.txt"
d = open(A,'rb').read()
ct_end = d  # whole file after header

def pr(b): return sum(1 for x in b if 32 <= x < 127 or x in (9,10,13))

pw = b"123"
counts = [1000, 5000, 10000, 50000, 100000, 200000, 210000, 250000, 310000, 500000, 600000, 1000000]

# try layout: [start] salt(len s), nonce 12, ct
layouts = []
for start in (31,32,35,36,40,44,48,52,56,60):
    for sl in (16,24,32):
        layouts.append((start, sl))

hits = []
for start, sl in layouts:
    salt = d[start:start+sl]
    if len(salt) != sl: continue
    for count in counts:
        for prfname, prffn in (("sha512", lambda p,s: hmac.new(p,s,hashlib.sha512).digest()),
                                ("sha256", lambda p,s: hmac.new(p,s,hashlib.sha256).digest())):
            key = PBKDF2(pw, salt, dkLen=32, count=count, prf=prffn)
            for noff in (start+sl, start+sl+16):
                nonce = d[noff:noff+12]
                ct = d[noff+12:]
                if len(nonce) != 12 or len(ct) < 64: continue
                ks = AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\x00\x00\x00\x02")
                x = bytes(a^b for a,b in zip(ks, ct[:16]))
                if pr(x) >= 12:
                    hits.append(("AESGCM", start, sl, count, prfname, noff, x))
            print(f"done start={start} sl={sl} count={count} {prfname}", flush=True)
print("HITS:", hits)
