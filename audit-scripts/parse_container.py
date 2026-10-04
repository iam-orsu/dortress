import struct

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\application1.exe"
data = open(P,'rb').read()
n = len(data)
start = 5113856
end = n - 16
cont = data[start:end]
print("container len:", len(cont))
print("magic:", cont[:4])
print("version:", cont[4])
print("passflag:", cont[5])
print("saltlen:", cont[6])
print("r:", cont[7], "p:", cont[8])
sl = cont[6]
off = 9
salt = cont[off:off+sl]; off+=sl
nonce = cont[off:off+12]; off+=12
ct = cont[off:]
print("salt:", salt.hex())
print("nonce:", nonce.hex())
print("ct len:", len(ct), "(=pt len + 16 tag)")
print("pt len would be:", len(ct)-16)

# also inspect DLK3 at 1402124 and 1507841
for o in (1402124, 1507841):
    print(f"\n@ {o}:", data[o:o+48].hex(), data[o:o+40])

# Look for .rdata / sections: quick PE section parse
import struct as st
pe = data[0x3c:0x40]
peoff = st.unpack('<I', pe)[0]
print("\nPE offset:", hex(peoff), data[peoff:peoff+4])
machine, nsec = st.unpack('<HH', data[peoff+4:peoff+8])
print("machine:", hex(machine), "sections:", nsec)
opt = peoff+24
magic = st.unpack('<H', data[opt:opt+2])[0]
print("opt magic:", hex(magic))
so = opt + (240 if magic==0x20b else 224)
for i in range(nsec):
    s = data[so+i*40: so+(i+1)*40]
    name = s[:8].rstrip(b'\x00')
    vsize, vaddr, rawsize, rawptr = st.unpack('<IIII', s[8:24])
    print(f"  {name.decode(errors='replace'):10} va={hex(vaddr):>10} vsize={vsize:>10} raw={hex(rawptr):>10} rawsize={rawsize}")
