# binscope

[![CI](https://github.com/philfunk/binscope/actions/workflows/ci.yml/badge.svg)](https://github.com/philfunk/binscope/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Code style: stdlib-only core](https://img.shields.io/badge/core-stdlib--only-success.svg)](pyproject.toml)
[![🤗 Live demo](https://img.shields.io/badge/%F0%9F%A4%97%20demo-Hugging%20Face%20Space-ffcc4d.svg)](https://huggingface.co/spaces/philippefunk/binscope)

A reverse-engineering and dynamic-analysis **orchestrator**. One program that
drives a suite of open-source binary-analysis tools through a single staged
pipeline and merges everything into one unified report.

> **▶ Try it now, nothing to install:** the [live in-browser demo](https://huggingface.co/spaces/philippefunk/binscope)
> runs binscope's triage on your file entirely client-side (WebAssembly Python).

It does **not** reimplement the tools — it runs the real ones (Ghidra, Rizin,
capa, angr, Frida, AFL++, native tracers), parses their output, and correlates
the results so you get "what does this binary actually do, and is there dormant
code?" from one command instead of six separate sessions.

> **Scope.** For authorized work only: malware defense, CTFs, security research,
> interoperability, forensics, debugging your own or a client's software. It
> deliberately has no DRM/license-bypass or anti-detection features.

## The pipeline

```
 triage ─▶ static (Ghidra + Rizin) ─▶ capabilities (capa)
        ─▶ reachability (angr) ─▶ dynamic (Frida / strace+ltrace) ─▶ fuzz (AFL++)
         static, never runs target │ execution stages (opt-in, sandbox only)
```

| Stage | Tool | What it contributes | Runs target? |
|---|---|---|---|
| `triage` | built-in | hashes, entropy, strings, crypto constants, suspicious-API strings | no |
| `ghidra` | Ghidra headless | decompiled C + a map of which functions touch network/crypto/file/process/registry/dynload APIs | no |
| `rizin` | Rizin (Cutter's engine) | functions, imports→capability mapping, exports, mitigations, large-function jump targets | no |
| `capa` | FLARE capa | ATT&CK / MBC capability matches | no |
| `angr` | angr | CFG + functions **unreachable from entry** (dormant/indirect-call candidates); optional "find an input that reaches address X" | no |
| `frida` | Frida | live trace of network/file/process/crypto/loader calls | **yes** |
| `systrace` | strace + ltrace | syscall / libcall trace (Linux) | **yes** |
| `fuzz` | AFL++ | time-boxed coverage-guided fuzzing → crashes/hangs with reproducers | **yes** |

Static stages are the default. The three execution stages refuse to run unless
you pass `--i-have-a-sandbox`, confirming a disposable, network-contained host.

## Install

binscope's core is pure standard library (Python ≥ 3.10):

```bash
pip install -e .            # installs the `binscope` command
pip install -e ".[all]"    # also installs capa, angr, frida-tools
```

The external native tools are installed separately. Check what you have:

```bash
binscope inventory
```

It prints each tool's status and a platform-specific install hint for the ones
you're missing. Ghidra is found via `GHIDRA_INSTALL_DIR` (needs JDK 21); AFL++,
strace, and ltrace are Linux-only and degrade to "skipped" elsewhere.

## Use

```bash
# Safe default: triage + Ghidra + Rizin + capa + angr. Never runs the target.
binscope analyze ./sample.bin -o ./out

# Preview what would run on this host, then exit.
binscope analyze ./sample.bin --dry-run

# Focus Ghidra on one subsystem and cap work on a big target.
binscope analyze ./app.dll --func-filter crypt --max-functions 200 --ghidra-timeout 600

# Ask angr whether any input reaches a specific address.
binscope analyze ./crackme --stages angr --angr-find 0x401337

# Full pipeline INCLUDING execution stages — inside a throwaway VM only.
binscope analyze /samples/x --stages all --i-have-a-sandbox \
    --frida-duration 30 --fuzz-duration 300 --fuzz-seeds ./seeds
```

Output goes to `<out>/report.json` (machine-readable) and `<out>/report.md`
(human-readable, with a stage table and findings ranked by severity). Every raw
tool output and exported artifact (decompiled C, strings, capa JSON, Frida log,
AFL crashes) is kept under `<out>/work/<stage>/` so you can re-derive any claim.

## Safety model

- Execution stages (`frida`, `systrace`, `fuzz`) are gated behind
  `--i-have-a-sandbox`; without it they report `refused` and the static stages
  still run.
- The target is always passed as an argument; binscope never `cd`s into its
  directory and never imports from it.
- Text found *inside* the target (strings, decompiled code) is reported as data,
  never executed as instructions.
- No stage ever disables security mitigations, strips license checks, or evades
  detection.

## Extending

Add a stage by subclassing `binscope.stages.base.Stage`, implementing `run()`,
and registering it in `binscope/stages/__init__.py`'s `REGISTRY`. Set
`executes_target = True` if it runs the binary, and `required_tool` to a key in
`binscope/tooling.py` to get automatic "tool missing" handling.

## Layout

```
binscope/
  cli.py          # argparse front-end: `inventory`, `analyze`
  pipeline.py     # plans + runs stages, assembles the Report
  config.py       # run configuration + stage sets
  tooling.py      # external-tool detection + install hints
  report.py       # Finding / StageResult / Report + JSON & Markdown renderers
  util.py         # subprocess, hashing, entropy, magic-byte sniffing
  stages/         # one module per stage (triage, ghidra, rizin, capa, angr, frida, systrace, fuzz)
  resources/
    DecompileExport.java  # Ghidra headless post-script (map + decompiled C)
    frida_trace.js        # cross-platform call tracer
```
