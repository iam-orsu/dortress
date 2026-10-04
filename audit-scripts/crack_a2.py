import hashlib, hmac
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import scrypt, PBKDF2

A = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\a.txt"
d = open(A,'rb').read()

def pr(b):
    return sum(1 for x in b if 32 <= x < 127 or x in (9,10,13))

pws = [b"123", b"hello world hack me !!!!", b"ZEUSBGV", b"hello world hack me !!!!ZEUSBGV",
       b"hack me", b"hello world", b"dortress", b"DORTRESS", b"", b"password", b"msbj"]
# key-material style: serial || '|' || combined ; combined = keyfile[|pass]
km_candidates = []
for pw in pws:
    km_candidates += [pw, b"|"+pw, pw+b"|", b"||"+pw, b"|"+pw+b"|", b"|||"]
km_candidates = list(dict.fromkeys(km_candidates))

layouts = []
for start in (31,32,35,36,40,44,48,52):
    for nonce_first in (False, True):
        layouts.append((start, nonce_first))

results = []
for start, nonce_first in layouts:
    if nonce_first:
        nonce = d[start:start+12]; salt = d[start+12:start+28]; ct = d[start+28:]
    else:
        salt = d[start:start+16]; nonce = d[start+16:start+28]; ct = d[start+28:]
    if len(salt)!=16 or len(nonce)!=12 or len(ct)<64: continue
    for km in km_candidates:
        keys = []
        for N in (1<<14, 1<<15, 1<<16):
            keys.append((f"scrypt{N}", scrypt(km, salt, 32, N=N, r=8, p=1)))
        keys.append(("pbkdf2-1k", PBKDF2(km, salt, dkLen=32, count=1000, prf=lambda p,s: hmac.new(p,s,hashlib.sha256).digest())))
        keys.append(("sha256", hashlib.sha256(km+salt).digest()))
        for kn, key in keys:
            ecb = AES.new(key, AES.MODE_ECB)
            ks = ecb.encrypt(nonce + b"\x00\x00\x00\x02")
            x = bytes(a^b for a,b in zip(ks, ct[:16]))
            sc = pr(x)
            if sc >= 13:
                results.append((sc,start,nonce_first,km,kn,"AESGCM",x))
            ch = ChaCha20.new(key=key, nonce=nonce); ch.seek(64)
            xc = bytes(a^b for a,b in zip(ch.encrypt(b"\x00"*16), ct[:16]))
            if pr(xc) >= 13:
                results.append((pr(xc),start,nonce_first,km,kn,"CHACHA",xc))

results.sort(reverse=True, key=lambda t:t[0])
print("candidates:", len(results))
for r in results[:20]:
    print(r)
print("sample head bytes:", d[:40])
