import hashlib, itertools, string
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import scrypt, PBKDF2

A = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\a.txt"
d = open(A, 'rb').read()
head = d[:44]
print("size", len(d), "head", head)

def printable(b):
    ok = sum(1 for x in b if 32 <= x < 127 or x in (9,10,13))
    return ok

pws = [b"123", b"1234", b"hello world hack me !!!!", b"hello world hack me !",
       b"ZEUSBGV", b"hello world hack me !!!!ZEUSBGV", b"hack me", b"hello world",
       b"dortress", b"DORTRESS", b"msbj", b"password", b"neelanjan", b"manna",
       b"DrNeelanjanManna", b"96269", b"scifiinc", b"SENTINEL", b"sentinel"]

splits = []
for start in (31, 32, 35, 36, 40, 44, 48):
    splits.append(("salt16+nonce12", start, 16, 12, False))
    splits.append(("nonce12+salt16", start, 12, 16, True))

def kdf_list(pw, salt):
    out = []
    for N in (1<<14, 1<<15, 1<<16):
        try:
            out.append((f"scrypt N={N}", scrypt(pw, salt, 32, N=N, r=8, p=1)))
        except Exception:
            pass
    for it in (10000, 100000, 600000):
        out.append((f"pbkdf2-{it}", PBKDF2(pw, salt, dkLen=32, count=it, prf=lambda p,s: hashlib.sha256(p+s).digest() if False else __import__('hmac').new(p, s, 'sha256').digest())))
    out.append(("sha256(pw+salt)", hashlib.sha256(pw+salt).digest()))
    out.append(("sha256(salt+pw)", hashlib.sha256(salt+pw).digest()))
    out.append(("sha256(pw)", hashlib.sha256(pw).digest()))
    return out

best = []
for name, start, l1, l2, swap in splits:
    if swap:
        nonce = d[start:start+l1]; salt = d[start+l1:start+l1+l2]; ct = d[start+l1+l2:]
    else:
        salt = d[start:start+l1]; nonce = d[start+l1:start+l1+l2]; ct = d[start+l1+l2:]
    if len(nonce) != 12 or len(salt) != 16 or len(ct) < 64:
        continue
    for pw in pws:
        for kname, key in kdf_list(pw, salt):
            # AES-GCM keystream block1
            try:
                ecb = AES.new(key, AES.MODE_ECB)
                ksA = ecb.encrypt(nonce + b"\x00\x00\x00\x02")
            except Exception:
                continue
            xa = bytes(a ^ b for a, b in zip(ksA, ct[:16]))
            # ChaCha20-Poly1305 keystream (counter=1)
            try:
                ch = ChaCha20.new(key=key, nonce=nonce)
                ch.seek(64)  # skip poly key block
                ksc = ch.encrypt(b"\x00"*16)
                xc = bytes(a ^ b for a, b in zip(ksc, ct[:16]))
            except Exception:
                xc = b""
            for tag, x in (("AESGCM", xa), ("CHACHA", xc)):
                sc = printable(x)
                if sc >= 12:
                    best.append((sc, name, start, pw, kname, tag, x))
best.sort(reverse=True, key=lambda t: t[0])
print("top candidates:")
for b in best[:25]:
    print(b)
