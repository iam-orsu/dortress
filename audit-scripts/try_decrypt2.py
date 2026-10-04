import hashlib, struct
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\application1.exe"
data = open(P,'rb').read(); n = len(data)
clen = struct.unpack('<q', data[-8:])[0]
cont = data[n-16-clen:n-16]
salt = cont[9:25]; nonce = cont[25:37]; ct = cont[37:]
print("container len", len(cont), "ct", len(ct))
AAD = hashlib.sha256(b"DORTRESS-USB-LOCK-v3|N=65536|r=8|p=1").digest()

def open_ct(km, aad):
    key = scrypt(km, salt, 32, N=1<<16, r=8, p=1)
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return c.decrypt_and_verify(ct, aad)
    except Exception:
        return None

serials = [b"03025311022023083804", b"03025311022023083804 ", b" 03025311022023083804",
           b"03025311022023083804\r", b"03025311022023083804\n", b"03025311022023083804\r\n",
           b"03 02 53 11 02 20 23 08 38 04", b"030253110220230838"]
passes = [b"123", b"", b"1234", b"password", b"dortress", b"ess"]
keyfiles = [b""]

found = False
for s in serials:
    for kf in keyfiles:
        for pw in passes:
            combos = set()
            combos.add(s + b"|" + kf)                    # no passphrase path
            combos.add(s + b"|" + kf + b"|" + pw)        # with passphrase
            combos.add(s + b"|" + pw)
            combos.add(s)
            for aad in (AAD, b""):
                for km in combos:
                    pt = open_ct(km, aad)
                    if pt is not None:
                        print("SUCCESS serial=", s, "keyfile=", kf, "pass=", pw, "aad0=", aad[:4], "ptlen", len(pt))
                        open(r"C:\Users\adversary\Desktop\RevEng\work\payload_decrypted.bin","wb").write(pt)
                        found = True
print("found:", found)
