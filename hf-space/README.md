---
title: binscope
emoji: 🔎
colorFrom: indigo
colorTo: gray
sdk: static
pinned: false
license: mit
---

# binscope — static binary triage (in-browser demo)

Upload a compiled binary and get [binscope](https://github.com/philfunk/binscope)'s
**static triage** — file type, architecture, entropy, notable strings,
suspicious API references, crypto constants, and a severity-ranked findings
table — computed **entirely in your browser**.

This is a **Static Space**: binscope's real triage code runs client-side via
[Pyodide](https://pyodide.org) (CPython compiled to WebAssembly). Your file
never leaves your browser and is never executed — binscope reads it, it doesn't
run it.

## Running the full pipeline

The browser demo is triage only. The full binscope pipeline — Ghidra
decompilation, Rizin, capa capabilities, angr reachability, and the execution
stages (Frida, strace/ltrace, AFL++) behind an explicit `--i-have-a-sandbox`
flag — runs locally:

```bash
pipx install git+https://github.com/philfunk/binscope.git
binscope analyze ./your.bin -o ./out
```

Scope: authorized analysis only — malware defense, CTFs, research,
interoperability, debugging. No DRM-bypass, cheats, or evasion.
