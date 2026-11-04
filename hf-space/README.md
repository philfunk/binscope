---
title: binscope — binary triage
emoji: 🔎
colorFrom: indigo
colorTo: gray
sdk: static
pinned: false
license: mit
short_description: In-browser static triage for compiled binaries (ELF/PE/Mach-O)
tags:
  - reverse-engineering
  - malware-analysis
  - security
  - binary-analysis
  - pyodide
---

# 🔎 binscope — static binary triage

**Upload a compiled binary and see what it's made of — right in your browser, nothing uploaded anywhere.**

binscope is a reverse-engineering and dynamic-analysis *orchestrator*: one tool
that drives Ghidra, Rizin, capa, angr, Frida, and AFL++ through a single
pipeline and merges their output into one report. This Space is its **triage**
stage, running live via [Pyodide](https://pyodide.org) (CPython in WebAssembly).

> 🔒 **Private & safe by design.** Your file **never leaves your browser** — the
> analysis runs client-side — and binscope **never executes** it. Triage reads
> bytes; it does not run code.

## What this demo shows you

| | |
|---|---|
| **File identity** | Magic-byte type (ELF / PE / Mach-O / …), architecture, bit-width, size, SHA-256 |
| **Entropy** | Overall Shannon entropy — a high value flags packing / encryption |
| **Strings of interest** | URLs, IPs, `.onion`, registry Run-keys, shell commands, `.pdb` paths |
| **Suspicious APIs** | `WriteProcessMemory`, `VirtualAlloc`, `LoadLibrary`, `IsDebuggerPresent`, … with byte offsets |
| **Crypto constants** | AES S-box, SHA-256 / MD5 init vectors — each with an offset to jump to |
| **Ranked findings** | Every result tagged (injection, persistence, network, crypto, anti-analysis…) and sorted by severity |

You also get the full report as **downloadable JSON** and a Markdown view.

## How it works

1. You pick a file; the bytes are read into the page (never sent to a server).
2. Pyodide boots a Python runtime in WebAssembly and `micropip`-installs the real
   `binscope` wheel — the *same code* that runs on the command line.
3. binscope's `triage` stage analyzes the bytes and returns a structured report,
   rendered as the table and JSON you see.

First load fetches the Python runtime (a few MB), so the very first analysis
takes ~10-20 s; after that it's instant.

## This is triage — the full tool does much more

The browser demo is deliberately limited to the safe, dependency-free `triage`
stage. The complete binscope pipeline adds:

- **Ghidra** headless decompilation to C, with a map of which functions touch network / crypto / file / process / registry / dynamic-load APIs
- **Rizin** (Cutter's engine) — functions, imports → capability mapping, mitigations
- **capa** — MITRE ATT&CK / MBC capability matches
- **angr** — control-flow graph + functions unreachable from entry (dormant / indirect-call candidates)
- **Frida** and **strace/ltrace** — live runtime call tracing *(executes the target)*
- **AFL++** — coverage-guided fuzzing for crashes *(executes the target)*

The execution stages run only behind an explicit `--i-have-a-sandbox` flag.
Run the whole thing locally:

```bash
pipx install git+https://github.com/philfunk/binscope.git
binscope inventory                      # see which tools you have
binscope analyze ./your.bin -o ./out    # safe static analysis -> report.md + report.json
```

## Links

- **Source & full pipeline:** https://github.com/philfunk/binscope
- **License:** MIT

> **Scope.** For authorized analysis only — malware defense, CTFs, security
> research, interoperability, and debugging your own or a client's software.
> binscope has no DRM-bypass, game-cheat, or detection-evasion features.
