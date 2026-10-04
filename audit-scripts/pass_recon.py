import json, base64, hashlib, os

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\pass.txt"
raw = open(P,'rb').read()
print("size", len(raw))
j = json.loads(raw)
for k,v in j.items():
    b = base64.b64decode(v + "="*((4-len(v)%4)%4))
    print(f"{k:12} b64len={len(v):6} bytes={len(b):5} head={b[:16].hex()}")

# compare with exe/other artifacts
D = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123"
for f in ('a.txt','application1.exe','a.png'):
    data = open(os.path.join(D,f),'rb').read()
    print(f"\n{f}:", "contains public_key?", j['public_key'][:20].encode() in data,
          "contains ciphertext?", j['ciphertext'][:20].encode() in data)
print("\nsha256(pub):", hashlib.sha256(base64.b64decode(j['public_key']+'==')).hexdigest())
