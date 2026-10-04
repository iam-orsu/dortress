import math, os, collections

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123"

def entropy(b):
    if not b: return 0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

for name in ('a.txt','application1.exe','pass.txt'):
    path = os.path.join(P,name)
    data = open(path,'rb').read()
    print(f"=== {name} size={len(data)} entropy={entropy(data[:1_000_000]):.4f} (first 1MB)")
    print("  head 64:", data[:64].hex())
    print("  tail 64:", data[-64:].hex())
    print("  tail asc:", ''.join(chr(x) if 32<=x<127 else '.' for x in data[-64:]))

# a.txt chunk entropy across the file
data = open(os.path.join(P,'a.txt'),'rb').read()
print("\na.txt block entropies (256KB blocks):")
for i in range(0, len(data), 256*1024):
    blk = data[i:i+256*1024]
    print(f"  off {i:>10} ({i/1024/1024:6.2f}MB) ent={entropy(blk):.4f} size={len(blk)}")
