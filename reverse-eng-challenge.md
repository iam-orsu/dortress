# Reverse Engineering Challenge: Dortress Technologies Security Assessment

## Environment Access

You have full access to:
- **WSL Ubuntu environment**: Run Linux tools via `wsl -d ubuntu` command
- **Windows environment**: Install tools via `scoop install <package>`
- **Sudo access**: No password required for root commands in WSL
- **File system**: Can read/write to all challenge files

## Your Mission

Reverse engineer and break a 4-part security challenge for Dortress Technologies Private Limited.

Files provided:
- a.png (26 KB)
- a.txt (33,037 KB)
- application1.exe (38,038 KB)
- pass.txt (12 KB)
- requirements.txt (1 KB)

## Challenge Requirements

### Task 1: PNG Content Modification + QR Jacking
- Modify a.png to display: "hello dr neelanjan manna you have been qr jacked and it must open in domain 96269.in"
- Extract the encryption password used in the PNG
- Verify the modified PNG contains the required message

### Task 2: a.txt Encryption Breaking
- Extract clear text content from a.txt
- Obtain the encryption password used
- Identify the encryption method (cipher type, key length, algorithm)

### Task 3: application1.exe Source Code Extraction
- Decompile application1.exe to human-readable source code
- Output must be in editable form (not binary disassembly)
- Identify the compiler, architecture, and any obfuscation techniques
- Provide reconstructed source code with comments

### Task 4: pass.txt Content Recovery
- Extract full content of pass.txt
- Constraint: First 4 characters are "msbj"
- Handle any obfuscation, encoding, or compression

## Your Approach

### Phase 1: Reconnaissance
Before attempting any task, perform full file analysis:
- Examine file headers and magic numbers
- Check for signatures (UPX packing, .NET assemblies, encryption markers)
- Identify file types and sizes
- Look for embedded data, metadata, or steganography
- Report findings for each file

### Phase 2: Method Identification
For each task, identify:
- What encryption/obfuscation is used
- What tools are required
- What approach will break it
- Estimated difficulty level

### Phase 3: Execution
Run the actual breaking/reversing process:
- Install required tools via scoop (Windows) or apt (WSL)
- Execute breaking methodology step by step
- Provide actual tool commands and code
- Show intermediate results

### Phase 4: Verification
Confirm each result:
- Validate output format and content
- Verify password correctness
- Check decompiled code runs/compiles
- Ensure modifications are accepted

## Tools You Can Use

### Windows Tools (install via scoop)



### Linux Tools (WSL Ubuntu)

wsl -d ubuntu apt update
wsl -d ubuntu apt install -y ghidra radare2 binutils strings nm objdump
wsl -d ubuntu apt install -y exiftool imagemagick pngcheck
wsl -d ubuntu apt install -y python3 pip3 hashcat john


### Command Format
- Windows tools: Run directly or via `scoop install <tool>`
- Linux tools: Use `wsl -d ubuntu <command>`
- Python scripts: Can run on either environment

## Delivery Format

For each task provide:

### Analysis
- What did you find in the file?
- What encryption/obfuscation method is used?
- What's the difficulty level?

### Methodology
- Step-by-step approach to break it
- Which tools are needed
- Why each tool works for this task

### Execution
- Exact commands to run (include full paths)
- Python code if needed (complete and runnable)
- Output from each command step
- Intermediate results

### Verification
- How you confirmed the result is correct
- Tests performed on extracted/modified content
- Proof the answer matches requirements

### Final Answer
- The extracted content
- The password
- The modified file (for PNG)
- The decompiled source code (for EXE)

## Report Order

1. File Reconnaissance Report
   - Header analysis for all files
   - Magic numbers and signatures
   - Packing/encryption indicators
   - Quick assessment of difficulty

2. Task 1: PNG Analysis and Breaking
   - PNG structure analysis
   - Embedded data identification
   - Modification strategy
   - Password extraction
   - Verification

3. Task 2: a.txt Decryption
   - Encryption method identification
   - Decryption approach
   - Password recovery
   - Clear text output
   - Verification

4. Task 3: application1.exe Decompilation
   - Binary analysis (architecture, compiler, protections)
   - Decompilation approach
   - Source code reconstruction
   - Verification and testing

5. Task 4: pass.txt Extraction
   - File format analysis
   - Obfuscation method
   - Extraction approach
   - Content verification

6. Final Checklist
   - All 4 tasks completed
   - All deliverables verified
   - No errors or missing content

## Important Notes

- No theories or vague answers. Provide exact commands and code.
- Every tool command must include full syntax and expected output.
- If something fails, diagnose why and provide alternative approach.
- Test all extracted content before finalizing.
- Assume these are real encryption/obfuscation techniques, not toy examples.
- Provide all Python code in complete, runnable form.
- Use WSL for Linux tools, scoop for Windows tools. Be explicit about which environment each command runs in.

## Start Here

Begin with Phase 1: Run file reconnaissance on all 4 files. Report what you find before attempting to break anything.