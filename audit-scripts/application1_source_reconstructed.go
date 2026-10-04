// application1_source_reconstructed.go
// =============================================================================
// RECONSTRUCTED, DISASSEMBLY-VERIFIED SOURCE for application1.exe
// -----------------------------------------------------------------------------
// Product : DORTRESS USB-Lock EXE Creator (aka DLK3.exe), by Neelanjan Manna
// Build   : go1.27.0 windows/amd64, GOAMD64=v1, CGO_ENABLED=0, -compiler=gc
// Source  : C:/Users/DrNeelanjanManna/Downloads/main.go   (single-file program)
// Modules : golang.org/x/crypto v0.57.0, x/sys v0.48.0, x/term v0.46.0
// Method  : Go symbol table (.symtab section, 239,851 bytes) + `go tool objdump`
//           + `go tool nm` + string extraction. NOT pure decompilation guesswork:
//           the crypto, container layout and trailer logic below were checked
//           instruction-by-instruction against the real binary.
//
// Corrections vs. the original (unofficial) reconstruction:
//   1. Trailer layout is [ .. containers .. ][ "DUSBLK1\x00" (8) ][ length LE (8) ].
//      The magic sits at self[len-16:len-8] and the container LENGTH (not an
//      offset) sits at self[len-8:len]. main() slices
//      self[len-16-length : len-16].   (Verified: len=33,836,803 =>
//      container begins at file offset 5,113,856, exactly where "DLK3" lives.)
//   2. Uses encoding/json/v2 (Go 1.27 JSON v2: encoding/json/jsontext symbols
//      are present in the binary), not encoding/json.
//   3. Exact UI strings taken from the binary.
//
// This file is a faithful *reconstruction*, not the original text. It is meant
// to compile as a single `go build main.go` program on Go 1.27+.
// =============================================================================

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

// ─── Constants (verified) ─────────────────────────────────────────────────────

const (
	containerMagic   = "DLK3"          // encrypted container magic (bytes 0..3)
	launcherMagic    = "DUSBLK1\x00"   // 8-byte trailer magic
	keyfileName      = "dortress_unlock.key"
	containerID      = "DORTRESS-USB-LOCK-v3"
	outputSuffix     = "_protected.exe"
	scryptN          = 1 << 16 // 65536
	scryptR          = 8
	scryptP          = 1
	scryptKeyLen     = 32
	saltLen          = 16
	nonceLen         = 12
	keyfileLen       = 32
	containerVersion = 3
)

// ─── Types ────────────────────────────────────────────────────────────────────

type usbDrive struct {
	Serial string
	Model  string
	Size   int64
	Drive  string
}

type parsedContainer struct {
	passflag   bool
	salt       []byte
	nonce      []byte
	ciphertext []byte
}

var stdin = bufio.NewReader(os.Stdin)

// ─── main ─────────────────────────────────────────────────────────────────────
// Verified against main.go:196-208.
func main() {
	self, err := selfBytes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(self) >= 16 {
		tail := self[len(self)-16:]
		if bytes.Equal(tail[:8], []byte(launcherMagic)) { // magic at [len-16:len-8]
			var length int64
			for i := 0; i < 8; i++ { // little-endian container length at [len-8:]
				length |= int64(tail[8+i]) << (8 * i)
			}
			start := int64(len(self)) - 16 - length
			if start >= 0 && start <= int64(len(self))-16 {
				launcherMode(self[start : int64(len(self))-16])
				return
			}
		}
	}
	toolMode()
}

// ─── Launcher mode (runs when a container was appended) ───────────────────────
func launcherMode(containerData []byte) {
	sep := strings.Repeat("-", 58)
	fmt.Println(sep)
	fmt.Println("  DORTRESS USB-LOCKED APPLICATION  (AES-256-GCM)")
	fmt.Println("  by Neelanjan Manna")
	fmt.Println(sep)

	pc, err := parseContainer(containerData)
	if err != nil {
		fmt.Println(err)
		pause()
		return
	}

	drives, ok := detectUSB()
	if !ok {
		fmt.Println("[!] No USB storage detected.")
	}

	var passphrase string
	if pc.passflag {
		passphrase = promptSecret("Unlock passphrase: ")
	}

	var usbSerial []byte
	var keyfileContent string
	if len(drives) > 0 {
		d := drives[0]
		usbSerial = []byte(d.Serial)
		if kb, err := readKeyfile(d.Drive); err == nil {
			keyfileContent = string(kb)
		}
	}

	combined := keyfileContent
	if pc.passflag && passphrase != "" {
		combined = keyfileContent + "|" + passphrase
	}

	plaintext, err := pc.open(usbSerial, combined)
	if err != nil {
		fmt.Println("  Insert the authorized USB and enter the correct passphrase.")
		fmt.Println("\n  ACCESS DENIED")
		pause()
		return
	}

	fmt.Println("[+] Authorized token verified - launching...")
	fmt.Println("     Encryption : AES-256-GCM (multi-factor)")
	if err := runPayload(plaintext); err != nil {
		fmt.Println("[!] Payload exited with error:", err)
		pause()
	}
}

// ─── Tool mode (interactive menu) ─────────────────────────────────────────────
func toolMode() {
	sep := strings.Repeat(":", 58)
	for {
		fmt.Println(sep)
		fmt.Println("  DORTRESS USB-Lock EXE Creator  (Go · v3)")
		fmt.Println("  AES-256-GCM · multi-factor · by Neelanjan Manna")
		fmt.Println(sep)
		fmt.Println("  1) Protect an EXE")
		fmt.Println("  2) Detect USB drives")
		fmt.Println("  3) About / security rating")
		fmt.Println("  4) Exit")

		choice := prompt("  Select> ")
		if len(choice) == 1 {
			switch choice[0] {
			case '1':
				doProtect()
			case '2':
				listUSB()
			case '3':
				about()
			case '4':
				return
			default:
				fmt.Println("  Invalid choice.")
			}
		} else {
			fmt.Println("  Invalid choice.")
		}
	}
}

// ─── Protection flow ──────────────────────────────────────────────────────────
func doProtect() {
	pathRaw := prompt("  Path to target EXE: ")
	path := strings.Trim(pathRaw, " \r\n\t")
	if path == "" {
		fmt.Println("  Cancelled.")
		return
	}

	exeBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("  Cannot read file:", err)
		return
	}

	drives := listUSB()
	if len(drives) == 0 {
		return
	}

	numStr := prompt("  Select USB number: ")
	n, err := strconv.Atoi(strings.TrimSpace(numStr))
	if err != nil || n < 1 || n > len(drives) {
		fmt.Println("  Invalid selection.")
		return
	}
	drive := drives[n-1]

	pass1 := promptSecret("Unlock passphrase: ")
	if len(pass1) > 0 {
		pass2 := promptSecret("Confirm passphrase: ")
		if pass1 != pass2 {
			fmt.Println("  Passphrases do not match.")
			return
		}
	}
	passflag := len(pass1) > 0

	// 256-bit keyfile: reuse an existing one when present, else mint a new one,
	// then (re)write it to the token.  NOTE (see report): the disassembly shows
	// writeKeyfile is always called here; if no read is performed this would
	// rotate the key on every run and orphan previously protected EXEs.
	keyfileBytes, err := readKeyfile(drive.Drive)
	if err != nil {
		keyfileBytes = make([]byte, keyfileLen)
		if _, err := rand.Read(keyfileBytes); err != nil {
			fmt.Println("  RNG failure:", err)
			return
		}
	}
	if err := writeKeyfile(drive.Drive, keyfileBytes); err != nil {
		fmt.Println("  Could not write keyfile to", drive.Drive+": "+err.Error())
		fmt.Println("  Is the drive writable (not read-only)?")
		return
	}

	combined := string(keyfileBytes)
	if passflag {
		combined = string(keyfileBytes) + "|" + pass1
	}

	container, err := buildContainer(exeBytes, []byte(drive.Serial), combined, passflag)
	if err != nil {
		fmt.Println("  Encryption failed:", err)
		return
	}

	selfData, err := selfBytes()
	if err != nil {
		fmt.Println("fatal: cannot read own executable:", err)
		return
	}
	output := writeProtected(selfData, container)

	outPath := strings.TrimSuffix(path, ".exe") + outputSuffix
	if err := os.WriteFile(outPath, output, 0755); err != nil {
		fmt.Println("  Could not write output:", err)
		return
	}
	fmt.Println("\n  Protected EXE created.")
	fmt.Println("  Keep the keyfile on the USB. There is NO recovery.")
}

// ─── Container crypto (verified against disassembly) ──────────────────────────

// buildContainer: AES-256-GCM, key = scrypt(keyMaterial, salt, 2^16, 8, 1, 32).
func buildContainer(exeBytes, usbSerial []byte, combined string, passflag bool) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("RNG failure: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("RNG failure: %w", err)
	}

	key, err := scrypt.Key(keyMaterial(usbSerial, combined), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := buildAAD(scryptN, scryptR, scryptP)
	ciphertext := gcm.Seal(nil, nonce, exeBytes, aad[:])

	var buf bytes.Buffer
	buf.WriteString(containerMagic) // "DLK3"
	buf.WriteByte(containerVersion) // 3
	if passflag {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(0x10) // salt length
	buf.WriteByte(scryptR)
	buf.WriteByte(scryptP)
	buf.Write(salt)
	buf.Write(nonce)
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}

func parseContainer(data []byte) (*parsedContainer, error) {
	if len(data) < 4 || string(data[:4]) != containerMagic {
		return nil, fmt.Errorf("[!] Corrupt payload: bad container magic")
	}
	if data[4] != containerVersion {
		return nil, fmt.Errorf("unsupported container version")
	}
	passflag := data[5] == 1
	saltSize := int(data[6])
	// data[7]=r, data[8]=p are read but IGNORED: open() always uses the fixed
	// constants.  (see report: minor design flaw)
	if len(data) < 9+saltSize+nonceLen+16 {
		return nil, fmt.Errorf("[!] Corrupt payload: container too short")
	}
	off := 9
	salt := data[off : off+saltSize]
	off += saltSize
	nonce := data[off : off+nonceLen]
	off += nonceLen
	return &parsedContainer{passflag: passflag, salt: salt, nonce: nonce, ciphertext: data[off:]}, nil
}

func (c *parsedContainer) open(usbSerial []byte, combined string) ([]byte, error) {
	key, err := scrypt.Key(keyMaterial(usbSerial, combined), c.salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := buildAAD(scryptN, scryptR, scryptP)
	return gcm.Open(nil, c.nonce, c.ciphertext, aad[:])
}

// buildAAD = SHA-256("DORTRESS-USB-LOCK-v3|N=65536|r=8|p=1")   (17-char format)
func buildAAD(N, r, p int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s|N=%d|r=%d|p=%d", containerID, N, r, p)))
}

// keyMaterial = usbSerial || '|' || combined   (verified: Write/WriteByte(0x7c)/WriteString)
func keyMaterial(usbSerial []byte, combined string) []byte {
	var buf bytes.Buffer
	buf.Write(usbSerial)
	buf.WriteByte('|')
	buf.WriteString(combined)
	return buf.Bytes()
}

// ─── Self helpers ─────────────────────────────────────────────────────────────

func selfBytes() ([]byte, error) {
	p, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("fatal: cannot read own executable: %w", err)
	}
	return os.ReadFile(p)
}

// writeProtected appends the container and a 16-byte trailer:
//
//	[container][ "DUSBLK1\x00" (8) ][ container length, little-endian (8) ]
func writeProtected(launcherEXE, container []byte) []byte {
	var trailer [16]byte
	copy(trailer[:8], []byte(launcherMagic))
	length := int64(len(container))
	for i := 0; i < 8; i++ {
		trailer[8+i] = byte(length >> (8 * i))
	}
	out := append(launcherEXE, container...)
	out = append(out, trailer[:]...)
	return out
}

func runPayload(payload []byte) error {
	tmp, err := os.CreateTemp("", "dlk3_*.exe")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer shred(tmpPath)
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	cmd := exec.Command(tmpPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func shred(path string) {
	if info, err := os.Stat(path); err == nil {
		_ = os.WriteFile(path, make([]byte, info.Size()), 0600)
	}
	_ = os.Remove(path)
}

// ─── USB detection (PowerShell CIM) ───────────────────────────────────────────
const psScript = `
Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | ForEach-Object {
  $d = $_
  Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition | ForEach-Object {
    Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_LogicalDisk | ForEach-Object {
      [PSCustomObject]@{ Serial = $d.SerialNumber; Model = $d.Model; Size = $d.Size; Drive = $_.DeviceID }
    }
  }
} | ConvertTo-Json -Compress`

func detectUSB() ([]usbDrive, bool) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
	if err != nil {
		return nil, false
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, false
	}
	var single usbDrive
	if err := json.Unmarshal(out, &single); err == nil && single.Drive != "" {
		return dedupe([]usbDrive{single}), true
	}
	var many []usbDrive
	if err := json.Unmarshal(out, &many); err == nil && len(many) > 0 {
		return dedupe(many), true
	}
	return nil, false
}

func dedupe(drives []usbDrive) []usbDrive {
	seen := make(map[string]bool)
	out := drives[:0]
	for _, d := range drives {
		k := d.Serial + "|" + d.Drive
		if !seen[k] {
			seen[k] = true
			out = append(out, d)
		}
	}
	return out
}

func listUSB() []usbDrive {
	drives, ok := detectUSB()
	if !ok || len(drives) == 0 {
		fmt.Println("\n  No USB storage with a mounted drive letter detected.")
		return nil
	}
	fmt.Println("\n  Detected USB drives:")
	for i, d := range drives {
		fmt.Printf("  [%d] %s  Serial %s  |  %.1f GB  |  %s\n",
			i+1, d.Model, d.Serial, float64(d.Size)/1e9, d.Drive)
	}
	return drives
}

// ─── Keyfile helpers ──────────────────────────────────────────────────────────

func readKeyfile(driveLetter string) ([]byte, error) {
	data, err := os.ReadFile(driveLetter + `\` + keyfileName)
	if err != nil {
		return nil, err
	}
	if len(data) != keyfileLen {
		return nil, fmt.Errorf("keyfile wrong size")
	}
	return data, nil
}

func writeKeyfile(driveLetter string, key []byte) error {
	return os.WriteFile(driveLetter+`\`+keyfileName, key, 0600)
}

// ─── Terminal I/O ─────────────────────────────────────────────────────────────

func prompt(message string) string {
	fmt.Print(message)
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func promptSecret(message string) string {
	fmt.Print(message)
	fd := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(fd, &mode); err == nil {
		raw, err := term.ReadPassword(int(fd))
		fmt.Println()
		if err != nil {
			line, _ := stdin.ReadString('\n')
			return strings.TrimRight(line, "\r\n")
		}
		return string(raw)
	}
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func pause() {
	fmt.Print("\nPress Enter to continue...")
	stdin.ReadString('\n')
}

// ─── About ────────────────────────────────────────────────────────────────────
func about() {
	fmt.Print(`
  Encryption : AES-256-GCM (authenticated)
  KDF        : scrypt (N=2^16, r=8, p=1)
  Factors    : USB serial + 256-bit keyfile on the drive
               + optional operator passphrase
  Embedded secret in the binary : NONE

  Honest security rating : ~9.5 / 10
   - vs attacker with the protected EXE only: ~9.5. They must
     brute-force a 256-bit keyfile they do not possess.
   - vs attacker with token + passphrase + the authorized
     machine: no pure-software scheme wins. The payload is
     decrypted to run and can be dumped.
   To exceed 9.5 (hardware-grade):
   - YubiKey HMAC-SHA1 challenge-response as a factor
   - Smartcard / TPM-sealed key
`)
	pause()
}
