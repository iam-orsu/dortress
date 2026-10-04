import hashlib, struct, itertools
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\application1.exe"
data = open(P,'rb').read()
n = len(data)
tail = data[-16:]
print("tail magic:", tail[:8], "len:", struct.unpack('<q', tail[8:])[0])
clen = struct.unpack('<q', tail[8:])[0]
cont = data[n-16-clen : n-16]
assert cont[:4] == b'DLK3', cont[:4]
print("container ok, len", len(cont))
ver = cont[4]; passflag = cont[5]; saltlen = cont[6]
r_ = cont[7]; p_ = cont[8]
salt = cont[9:9+saltlen]
nonce = cont[9+saltlen:9+saltlen+12]
ct = cont[9+saltlen+12:]
print("ver",ver,"passflag",passflag,"saltlen",saltlen,"r",r_,"p",p_)
print("salt",salt.hex(),"nonce",nonce.hex(),"ct",len(ct))

AAD = hashlib.sha256(b"DORTRESS-USB-LOCK-v3|N=65536|r=8|p=1").digest()

def try_open(km, aad, N=1<<16, r=8, p=1):
    try:
        key = scrypt(km, salt, 32, N=N, r=r, p=p)
    except Exception as e:
        return None
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = c.decrypt_and_verify(ct, aad if aad is not None else b'')
        return pt
    except Exception:
        return None

serial_guesses = [b"", b"123", b"1234"]
combined_guesses = [b"", b"123", b"dortress", b"DORTRESS", b"dortress_unlock.key",
                    b"DLK3", b"DORTRESS-USB-LOCK-v3", b"password", b"admin"]
pass_guesses = [b"", b"123", b"1234", b"dortress", b"DORTRESS"]

found = []
candidates = set()
for s in serial_guesses:
    for comb in combined_guesses:
        candidates.add(s + b"|" + comb)
    for pw in pass_guesses:
        candidates.add(s + b"|" + pw)         # combined=keyfile(empty)+? 
        candidates.add(s + b"|" + b"" + b"|" + pw)  # keyfile empty + '|' + pass
        candidates.add(s + b"|" + pw + b"|" + pw)

for km in sorted(candidates):
    for aad in (AAD, b"", None):
        pt = try_open(km, aad)
        if pt is not None:
            print("SUCCESS km=", km, "aad=", aad, "pt len", len(pt))
            open(r"C:\Users\adversary\Desktop\RevEng\work\payload_decrypted.bin","wb").write(pt)
            found.append((km,aad))
print("done, found:", found)
