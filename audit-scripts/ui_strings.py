import re
P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\application1.exe"
data = open(P,'rb').read()
strs = set()
for m in re.finditer(rb'[\x20-\x7e]{4,120}', data):
    s = m.group().decode('latin1')
    # UI-looking: starts with spaces, or contains typical words
    if (s.startswith('  ') and not s.startswith('   ')) or any(k in s for k in
        ['USB','passphrase','Passphrase','keyfile','Keyfile','Protected','protected',
         'container','Container','EXE','Shred','shred','DORTRESS','Dortress','purpose',
         'Key','vault','Vault','token','Token','AUTHORIZED','ACCESS','rating','Rating',
         'scrypt','AES','Enter','Select','Path','Confirm','authorized']):
        if len(s) <= 90:
            strs.add(s)
for s in sorted(strs):
    print(repr(s))
