# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-04

### Added
- Initial release: staged orchestrator for reverse-engineering and dynamic
  analysis of compiled binaries.
- Pipeline stages: `triage`, `ghidra`, `rizin`, `capa`, `angr`, `frida`,
  `systrace`, `fuzz`.
- Unified report in JSON and Markdown, findings ranked by severity with
  reproducible coordinates; all raw tool output retained under `out/work/`.
- Tool detection (`binscope inventory`) with per-platform install hints.
- Safety gate: execution stages require `--i-have-a-sandbox`.
- Bundled Ghidra headless post-script (`DecompileExport.java`) and Frida
  tracer (`frida_trace.js`).
