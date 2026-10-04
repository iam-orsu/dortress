# Dortress Technologies - Reverse Engineering Challenge Progress

## Key Discovery: PASSWORD = `123`
- Folder name: `DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123`
- Password for all encryption = **123**

---

## File Inventory

| File | Size | Magic | Type |
|------|------|-------|------|
| a.png | 26 KB | `89 50 4E 47` | Valid PNG |
| a.txt | 33 MB | `hello world hack me !!!!ZEUSBGV` + binary | AES-256-GCM container |
| application1.exe | 38 MB | `MZ` PE64 | Go x64 binary |
| pass.txt | 12 KB | `{` JSON | Hybrid crypto JSON |
| requirements.txt | 660 B | text | Task description |

---

## Task 1: a.png (QR Jacking)

**Status**: TODO

**Goal**: Modify to display: *"hello dr neelanjan manna you have been qr jacked and it must open in domain 96269.in"*

**Approach**:
1. Inspect PNG for embedded data / steganography (exiftool, pngcheck, zsteg)
2. Find any QR code inside
3. Generate new QR code pointing to 96269.in with the message text
4. Replace/overwrite QR in the PNG
5. Extract encryption password from metadata or embedded data

---

## Task 2: a.txt Decryption

**Status**: IN PROGRESS

**Container Format**:
```
Offset 0x00-0x17 (24 bytes): "hello world hack me !!!!"
Offset 0x18-0x1E (7 bytes):  "ZEUSBGV"  ← custom magic
Offset 0x1F      (1 byte):   0x01       ← version
Offset 0x20-0x23 (4 bytes):  00 00 00 00
Offset 0x24+:    binary data (likely salt, nonce, ciphertext)
```

**Encryption**: AES-256-GCM (confirmed from application1.exe strings)

**Key Derivation**: scrypt (confirmed from binary strings: "scrypt: N must be > 1 and a power of 2")

**"ZEUSBGV" magic**: Found in application1.exe binary as container magic for standalone file encryption

**Required**: Password ("123") + USB serial + keyfile (dortress_unlock.key on USB)

**USB Drive**: G: \ SSS_X64FREE_EN-US_DV9 — checking for dortress_unlock.key

**Next**: Run application1.exe with USB inserted and password "123"

---

## Task 3: application1.exe Decompilation

**Status**: ANALYZED

**Binary Type**: Go x64 PE executable (38 MB)
- Build ID: `3fb2bkymjjV0qg_Aqh9i/...`
- Compiled with: Go (standard toolchain)
- Source path: `C:/Program Files/Go/src/...`

**Application Name**: "DORTRESS USB-LOCKED APPLICATION (AES-256-GCM) by Neelanjan Manna"
**Internal name**: DLK3.exe (Dortress Lock v3)
**Format**: DORTRESS-USB-LOCK-v3

**Key Function Names (preserved in Go binary)**:
- `main.main` — entry point
- `main.launcherMode` — runs embedded encrypted payload
- `main.toolMode` — file encryption/decryption tool mode
- `main.buildContainer` — builds encrypted container
- `main.parseContainer` — parses/decodes container
- `main.(*parsedContainer).open` — decrypts container
- `main.deriveKey` — key derivation (scrypt)
- `main.keyMaterial` — builds key material from USB serial + keyfile + passphrase
- `main.buildAAD` — builds Additional Authenticated Data for AES-GCM
- `main.detectUSB` — detects USB drives via PowerShell CIM
- `main.listUSB` — lists connected USB drives
- `main.writeKeyfile` — writes dortress_unlock.key to USB
- `main.readKeyfile` — reads dortress_unlock.key from USB
- `main.writeProtected` — writes protected EXE
- `main.appendedContainer` — reads payload appended to EXE
- `main.runPayload` — decrypts and runs embedded payload
- `main.shred` — securely deletes files
- `main.selfBytes` — reads own executable bytes
- `main.doProtect` — main protection/encryption flow
- `main.about` — shows about/security info
- `main.promptSecret` — reads passphrase from terminal

**Security Model (from about screen)**:
```
Encryption : AES-256-GCM (authenticated)
Factors    : USB serial + 256-bit keyfile on the drive
             + optional operator passphrase
Embedded secret in the binary : NONE
Honest security rating : ~9.5 / 10
```

**USB Detection**: Uses PowerShell `Get-CimInstance Win32_DiskDrive`

**Decompilation Approach**:
- Go binaries preserve all function/symbol names → use `go tool objdump` or Ghidra
- Source reconstruction via radare2 / Ghidra with Go plugin
- Key source paths: `C:/Program Files/Go/src/`

---

## Task 4: pass.txt Content Recovery

**Status**: ANALYZED

**Format**: JSON hybrid encryption
```json
{
  "signature": "<base64 RSA/ECDSA signature>",
  "public_key": "<base64 2048-bit public key>",
  "nonce": "StL1boekGgvDrqjB",      // 12-byte AES-GCM nonce
  "auth_tag": "DOa3PdtZY/LjsOuR80WXGw==",  // 16-byte GCM tag
  "ciphertext": "<base64 encrypted data>",
  "kem_cipher": "<base64 ML-KEM/Kyber ciphertext>"
}
```

**First 4 chars of plaintext**: `msbj`

**Encryption Scheme**:
- ML-KEM (Kyber) for key encapsulation
- AES-256-GCM for symmetric encryption
- RSA/ECDSA signature for authentication

**Constraint**: Need private key corresponding to `public_key` to decapsulate `kem_cipher`

**Libraries found in binary**: `tlsmlkem`, `tlskyber` (post-quantum crypto)

---

## Application1.exe Runtime Behaviour

When launched (launcher mode):
1. Shows DORTRESS USB-LOCKED APPLICATION banner
2. Runs PowerShell to detect USB via `Win32_DiskDrive` 
3. If USB found: reads serial + reads `dortress_unlock.key` from USB root
4. Prompts for passphrase
5. Derives AES-256-GCM key: `scrypt(USB_serial + keyfile_content + passphrase)`
6. Decrypts appended container (the embedded payload)
7. Runs decrypted payload in memory

---

## Tools Needed

- WSL Ubuntu: `strings`, `objdump`, `file`, `xxd`
- Python 3: `pycryptodome`, `scrypt` for manual decryption
- Ghidra / radare2: for deeper decompilation
- scoop: `zsteg`, `exiftool` for PNG analysis
- `qrencode` or Python `qrcode` for QR generation
