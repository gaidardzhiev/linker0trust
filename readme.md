# linker0trust PoC Malicious ELF Linker

## Overview

`linker0trust` is a security demonstration project showing the dangers of implicitly trusting the build toolchain, specifically the linker phase. This proof of concept implements a malicious linker in C that injects unauthorized code into ELF64 binaries at link time by appending a payload segment. The injected payload prints a message upon program start, illustrating how compromised or malicious linkers can tamper with binaries stealthily.

## The Danger of Trusting the Linker

Build toolchains are critical parts of software supply chains. Developers naturally trust linkers to combine compiled code and libraries into executable programs faithfully. However, this trust creates a huge attack surface: a malicious or compromised linker can silently inject harmful code without leaving obvious traces in source or binary signatures.

Unlike runtime exploits, this attack happens before the final executable distribution, making it extremely stealthy, difficult to detect, and capable of compromising any software trusting that toolchain.

Common risks include:
- Payloads executing with full user privileges before the main program starts
- Stealthy code that evades traditional binary inspection
- Supply chain compromises embedded deeply in the development lifecycle

This project vividly demonstrates this threat by injecting a simple payload that prints a message, but real attackers can replace it with arbitrary code.

## How linker0trust Works

### ELF Validation

- The program starts by reading and validating the input file to confirm it as a 64bit x86 ELF executable.
- It verifies ELF magic, architecture, program header availability, and consistency checks to prevent malformed inputs.

### Segment Analysis

- It scans loadable segments in the ELF to find the maximum file offset and virtual address extents.
- Identifies the greatest alignment among segments to place injected code properly aligned in memory.

### Payload Assembly

- Builds a compact `x86_64` assembly shellcode that:
  - Saves registers (`rdi`, `rsi`, `rdx`) to preserve processor state for crt1 expectations
  - Executes a `write` syscall to print the payload message (e.g., ">>> !!! payload executed !!! <<<")
  - Restores registers
  - Jumps back to the original program entry point, ensuring normal program execution

### Payload Injection & ELF Modification

- Aligns and appends the payload as a new loadable segment at the end of the binary in both file and virtual address space.
- Updates ELF headers:
  - Increments the number of program headers
  - Moves the program header table to follow the injected payload
  - Sets the ELF entry point to the payload virtual address, so execution starts with the injected code

### Output Generation

- Writes the modified ELF file, combining original input data with injected payload and updated headers.
- Reports injection locations and entry point changes.

## Key Technical Insights

- **Alignment**: Proper memory alignment (page sizes or larger) is critical for the injected segment to be executable and accessible.
- **Program Headers**: Manipulating ELF program headers is necessary to make the new payload segment discoverable and loaded by the OS loader.
- **Register Preservation**: Preserving entry registers is important for compatibility with standard CRT startup code expectations.
- **Relative Addressing**: Shellcode uses RIP relative addressing for the payload message, requiring careful calculation of relative offsets.
- **Payload Size Calculation**: Combines stub shellcode opcode length and message length dynamically to correctly size the injected segment.
- **Robust Validation**: Input ELF verification ensures the program only modifies valid, expected ELF binaries to avoid corruption.

## Security Implications

This demonstration sheds light on an often overlooked but critical risk in software supply chains. Because linkers act as black boxes, they can be subverted to insert backdoors, spyware, ransomware, or other malicious payloads undetectable by source audits or most binary scanning tools.

To mitigate:
- Use reproducible builds and binary transparency techniques
- Perform static and dynamic verification of binaries independent of build toolchains
- Employ runtime protections such as address space layout randomization (ASLR) and control flow integrity (CFI)
- Harden the development environment and supply chain security

## Usage

Build the malicious linker:

```
make
```


Build a test static non PIE binary:

```
gcc -no-pie -static -o test.o test.c
```


Inject payload and generate the malicious ELF:

```
./linker test.o out.elf
chmod +x out.elf
```


Run the injected binary:

```
./out.elf
```

You will see the injected payload message printed before the original program runs.

## Disclaimer

This project is intended **only** for educational and experimental purposes to demonstrate linker level threats. Do not use on software without permission.

---

This PoC illustrates the critical need for securing the entire software build and supply chain, especially the often underestimated linker phase, to maintain software integrity and trust.

