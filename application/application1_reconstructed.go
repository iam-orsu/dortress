// Reconstructed source code of application1.exe
// DORTRESS USB-Lock EXE Creator (Go · v3)
// Original author: Neelanjan Manna
// Reconstruction by: Reverse engineering analysis (symbols, strings, disassembly)
// Source path in binary: C:/Users/DrNeelanjanManna/Downloads/main.go

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

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	containerMagic   = "DLK3"              // 4-byte magic for encrypted container format
	launcherMagic    = "DUSBLK1\x00"       // 8-byte magic appended to launcher EXE (padded to 8)
	keyfileName      = "dortress_unlock.key"
	containerID      = "DORTRESS-USB-LOCK-v3"
	outputSuffix     = "_protected.exe"
	scryptN          = 1 << 16 // 65536
	scryptR          = 8
	scryptP          = 1
	scryptKeyLen     = 32
	saltLen          = 16
	nonceLen         = 12
	keyfileLen       = 32 // 256-bit keyfile
	containerVersion = 3
)

// ─── Types ────────────────────────────────────────────────────────────────────

// usbDrive holds information about a connected USB storage device.
// Fields match the JSON output of the PowerShell detection script.
type usbDrive struct {
	Serial string
	Model  string
	Size   int64
	Drive  string // e.g. "D:"
}

// parsedContainer holds the parsed fields of a DLK3 encrypted container.
type parsedContainer struct {
	passflag   bool   // whether an operator passphrase was set
	salt       []byte // 16-byte scrypt salt
	nonce      []byte // 12-byte AES-GCM nonce
	ciphertext []byte // encrypted payload + 16-byte GCM tag
}

// ─── Global ───────────────────────────────────────────────────────────────────

// stdin is used as a fallback reader when the terminal is not a real TTY.
var stdin = bufio.NewReader(os.Stdin)

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	self, err := selfBytes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Check whether this EXE has a DUSBLK1 launcher container appended.
	// Format of the last 16 bytes when in launcher mode:
	//   [0..7]  = "DUSBLK1\x00"  (magic)
	//   [8..15] = container offset from start of file (little-endian int64)
	if len(self) >= 16 {
		tail := self[len(self)-16:]
		magic := tail[:8]
		if bytes.Equal(magic, []byte(launcherMagic)) {
			// Read container offset (last 8 bytes)
			var off int64
			for i := 0; i < 8; i++ {
				off |= int64(tail[8+i]) << (8 * i)
			}
			if off >= 0 && int64(len(self))-off >= 16 {
				containerData := self[off : int64(len(self))-16]
				launcherMode(containerData)
				return
			}
		}
	}

	toolMode()
}

// ─── Launcher mode ────────────────────────────────────────────────────────────

// launcherMode runs when this EXE has a protected payload appended.
// It authenticates the USB token and, on success, decrypts and executes the payload.
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
		d := drives[0] // use first detected USB drive
		usbSerial = []byte(d.Serial)
		kb, err := readKeyfile(d.Drive)
		if err == nil {
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

// ─── Tool mode ────────────────────────────────────────────────────────────────

// toolMode is the interactive EXE-protection tool menu.
func toolMode() {
	sep := strings.Repeat(":", 58)
	for {
		fmt.Println(sep)
		fmt.Println("  DORTRESS USB-Lock EXE Creator  (Go \u00b7 v3)")
		fmt.Println("  AES-256-GCM \u00b7 multi-factor \u00b7 by Neelanjan Manna")
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

// doProtect guides the user through protecting an EXE with the USB token.
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
	pass2 := promptSecret("Confirm passphrase: ")
	if pass1 != pass2 {
		fmt.Println("  Passphrases do not match.")
		return
	}

	passflag := len(pass1) > 0

	// Read existing keyfile or generate a new 256-bit one.
	keyfileBytes, err := readKeyfile(drive.Drive)
	if err != nil {
		keyfileBytes = make([]byte, keyfileLen)
		if _, err := rand.Read(keyfileBytes); err != nil {
			fmt.Println("  RNG failure:", err)
			return
		}
		if err := writeKeyfile(drive.Drive, keyfileBytes); err != nil {
			fmt.Println("  Could not write keyfile to", drive.Drive+": "+err.Error())
			fmt.Println("  Is the drive writable (not read-only)?")
			return
		}
	}

	// Combine keyfile content with passphrase if supplied.
	combined := string(keyfileBytes)
	if passflag {
		combined = string(keyfileBytes) + "|" + pass1
	}

	container, err := buildContainer(exeBytes, []byte(drive.Serial), combined, passflag)
	if err != nil {
		fmt.Println("  Encryption failed:", err)
		return
	}

	// Build output: self-executable + DUSBLK1 launcher container
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

	fmt.Println("\n  \u2705 Protected EXE created.")
	fmt.Println("\n  Keep the keyfile on the USB. There is NO recovery.")
}

// ─── Container building ───────────────────────────────────────────────────────

// buildContainer encrypts exeBytes into a DLK3 container.
//   usbSerial   – raw serial bytes of the USB drive
//   combined    – keyfile content, optionally suffixed with "|passphrase"
//   passflag    – true if an operator passphrase is part of the key material
func buildContainer(exeBytes, usbSerial []byte, combined string, passflag bool) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("RNG failure: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("RNG failure: %w", err)
	}

	km := keyMaterial(usbSerial, combined)

	key, err := scrypt.Key(km, salt, scryptN, scryptR, scryptP, scryptKeyLen)
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

	// Serialise the DLK3 container:
	//   "DLK3"            4 bytes  – magic
	//   0x03              1 byte   – container version
	//   passflag (0/1)    1 byte
	//   0x10              1 byte   – salt length (16)
	//   0x08              1 byte   – scrypt r
	//   0x01              1 byte   – scrypt p
	//   salt              16 bytes
	//   nonce             12 bytes
	//   ciphertext+tag    variable
	var buf bytes.Buffer
	buf.WriteString(containerMagic)
	buf.WriteByte(containerVersion)
	if passflag {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(0x10)
	buf.WriteByte(scryptR)
	buf.WriteByte(scryptP)
	buf.Write(salt)
	buf.Write(nonce)
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// parseContainer parses a raw DLK3 container into a parsedContainer.
func parseContainer(data []byte) (*parsedContainer, error) {
	if len(data) < 4 || string(data[:4]) != containerMagic {
		return nil, fmt.Errorf("[!] Corrupt payload: bad container magic")
	}
	if data[4] != containerVersion {
		return nil, fmt.Errorf("unsupported container version")
	}
	passflag := data[5] == 1
	saltSize := int(data[6])
	// data[7] = r, data[8] = p (stored but currently fixed)
	if len(data) < 9+saltSize+nonceLen+16 {
		return nil, fmt.Errorf("[!] Corrupt payload: container too short")
	}
	off := 9
	salt := data[off : off+saltSize]
	off += saltSize
	nonce := data[off : off+nonceLen]
	off += nonceLen
	ciphertext := data[off:]
	return &parsedContainer{
		passflag:   passflag,
		salt:       salt,
		nonce:      nonce,
		ciphertext: ciphertext,
	}, nil
}

// open decrypts the parsedContainer and returns the plaintext payload.
//   usbSerial – raw bytes of the USB drive's serial number
//   combined  – keyfile content (with "|passphrase" appended when passflag is true)
func (c *parsedContainer) open(usbSerial []byte, combined string) ([]byte, error) {
	km := keyMaterial(usbSerial, combined)

	key, err := scrypt.Key(km, c.salt, scryptN, scryptR, scryptP, scryptKeyLen)
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

// buildAAD derives the Additional Authenticated Data for AES-GCM.
// AAD = SHA-256( "DORTRESS-USB-LOCK-v3|N=<N>|r=<r>|p=<p>" )
func buildAAD(N, r, p int) [32]byte {
	s := fmt.Sprintf("%s|N=%d|r=%d|p=%d", containerID, N, r, p)
	return sha256.Sum256([]byte(s))
}

// keyMaterial combines the USB serial and the keyfile (plus optional passphrase)
// into the scrypt password input:  serial || "|" || combined
func keyMaterial(usbSerial []byte, combined string) []byte {
	var buf bytes.Buffer
	buf.Write(usbSerial)
	buf.WriteByte('|')
	buf.WriteString(combined)
	return buf.Bytes()
}

// ─── Self-executable helpers ──────────────────────────────────────────────────

// selfBytes reads and returns the bytes of the currently running executable.
func selfBytes() ([]byte, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("fatal: cannot read own executable: %w", err)
	}
	return os.ReadFile(path)
}

// writeProtected appends a DLK3 container to the launcher EXE and adds
// the DUSBLK1 trailer that records the container's start offset.
//
// Layout of the output file:
//   [launcher EXE bytes]
//   [DLK3 container bytes]
//   [8-byte container start offset, little-endian]
//   [8-byte DUSBLK1\x00 magic]  ← last 16 bytes
func writeProtected(launcherEXE, container []byte) []byte {
	offset := int64(len(launcherEXE))
	var trailer [16]byte
	// Last 8 bytes = DUSBLK1\0
	copy(trailer[8:], []byte(launcherMagic))
	// First 8 bytes = container offset (little-endian)
	for i := 0; i < 8; i++ {
		trailer[i] = byte(offset >> (8 * i))
	}
	out := append(launcherEXE, container...)
	out = append(out, trailer[:]...)
	return out
}

// runPayload decrypts the payload (another EXE) and executes it in memory.
// The payload is written to a temp file, executed, then shredded.
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
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// shred overwrites a file with zeros then deletes it.
func shred(path string) {
	if info, err := os.Stat(path); err == nil {
		zeros := make([]byte, info.Size())
		_ = os.WriteFile(path, zeros, 0600)
	}
	_ = os.Remove(path)
}

// ─── USB detection ────────────────────────────────────────────────────────────

// PowerShell script that enumerates USB drives and their mounted drive letters,
// then outputs a JSON array of { Serial, Model, Size, Drive } objects.
const psScript = `
Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | ForEach-Object {
  $d = $_
  Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition | ForEach-Object {
    Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_LogicalDisk | ForEach-Object {
      [PSCustomObject]@{ Serial = $d.SerialNumber; Model = $d.Model; Size = $d.Size; Drive = $_.DeviceID }
    }
  }
} | ConvertTo-Json -Compress`

// detectUSB runs the PowerShell USB enumeration script and returns all
// connected USB drives that have a mounted drive letter.
// Returns (drives, true) on success; (nil, false) if nothing is found.
func detectUSB() ([]usbDrive, bool) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
	if err != nil {
		return nil, false
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, false
	}

	// PowerShell emits either a single JSON object or a JSON array depending on
	// how many drives are present.  Try both unmarshal forms.
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

// dedupe removes duplicate entries from a drive list (same Serial + Drive).
func dedupe(drives []usbDrive) []usbDrive {
	seen := make(map[string]bool)
	out := drives[:0]
	for _, d := range drives {
		key := d.Serial + "|" + d.Drive
		if !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	return out
}

// listUSB detects, prints, and returns USB drives.  Returns nil if none found.
func listUSB() []usbDrive {
	drives, ok := detectUSB()
	if !ok || len(drives) == 0 {
		fmt.Println("\n  No USB storage with a mounted drive letter detected.")
		return nil
	}
	fmt.Println("\n  Detected USB drives:")
	for i, d := range drives {
		gb := float64(d.Size) / 1e9
		fmt.Printf("  [%d] %s  Serial %s  |  %.1f GB  |  %s\n",
			i+1, d.Model, d.Serial, gb, d.Drive)
	}
	return drives
}

// ─── Keyfile helpers ──────────────────────────────────────────────────────────

// readKeyfile reads the 256-bit keyfile from the USB drive root.
func readKeyfile(driveLetter string) ([]byte, error) {
	path := driveLetter + `\` + keyfileName
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != keyfileLen {
		return nil, fmt.Errorf("keyfile wrong size")
	}
	return data, nil
}

// writeKeyfile writes a 32-byte keyfile to the USB drive root.
func writeKeyfile(driveLetter string, key []byte) error {
	path := driveLetter + `\` + keyfileName
	return os.WriteFile(path, key, 0600)
}

// ─── Terminal I/O ─────────────────────────────────────────────────────────────

// prompt prints a prompt and reads a line of input (max 10 chars buffer displayed).
func prompt(message string) string {
	fmt.Print(message)
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// promptSecret prints a prompt and reads a passphrase without terminal echo.
// Falls back to buffered stdin line-reading when not attached to a real console.
func promptSecret(message string) string {
	fmt.Print(message)

	// Attempt to use the Windows console handle for echo-suppressed input.
	fd := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(fd, &mode); err == nil {
		// Real console: use golang.org/x/term for password reading.
		raw, err := term.ReadPassword(int(fd))
		fmt.Println() // move to next line after hidden input
		if err != nil {
			// Fall back to plain read.
			line, _ := stdin.ReadString('\n')
			return strings.TrimRight(line, "\r\n")
		}
		return string(raw)
	}

	// Not a console (piped / redirected): read a plain line.
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// pause waits for the user to press Enter.
func pause() {
	fmt.Print("\nPress Enter to continue...")
	stdin.ReadString('\n')
}

// ─── About ────────────────────────────────────────────────────────────────────

// about prints the security model and rating, then pauses.
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
