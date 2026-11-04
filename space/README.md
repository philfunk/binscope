---
title: binscope
emoji: 🔎
colorFrom: indigo
colorTo: gray
sdk: gradio
sdk_version: 4.44.1
app_file: app.py
pinned: false
license: mit
---

# binscope — static binary triage (demo)

Upload a compiled binary and get [binscope](https://github.com/philfunk/binscope)'s
**static triage**: file type, architecture, entropy, notable strings,
suspicious API references, crypto constants, and a severity-ranked findings
table, plus the full report as JSON.

## Safety

This Space runs **only the `triage` stage**, which reads the file and never
executes it. binscope's dynamic and fuzzing stages (Frida, strace/ltrace,
AFL++) are intentionally unavailable here — running untrusted binaries belongs
in a disposable, network-contained sandbox, not a shared public Space.

For the full pipeline (Ghidra decompilation, Rizin, capa capabilities, angr
reachability, and the execution stages behind an explicit sandbox flag), run
binscope locally:

```bash
pipx install git+https://github.com/philfunk/binscope.git
binscope analyze ./your.bin -o ./out
```

Scope: authorized analysis only — malware defense, CTFs, research,
interoperability, debugging. No DRM-bypass, cheats, or evasion.
