# Contributing to binscope

Thanks for your interest in improving binscope. It's an orchestrator: it drives
external reverse-engineering tools and merges their output. Most contributions
are either a new **stage** (wrapping another tool) or improvements to parsing
and correlation in an existing one.

## Development setup

```bash
git clone <your-fork-url>
cd binscope
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Run the checks the CI runs:

```bash
python -m compileall binscope
pytest -q
ruff check binscope        # if ruff is installed
```

The test suite is pure-Python and does **not** require Ghidra, Rizin, capa,
angr, Frida, or AFL++ to be installed — stages whose tool is absent are
expected to report `tool_missing`, and the tests assert that graceful
degradation rather than the tools' output.

## Adding a new stage

1. Create `binscope/stages/<name>.py` with a class subclassing
   `binscope.stages.base.Stage`.
2. Set `name`, `tool`, and `required_tool` (a key in `binscope/tooling.py`).
   Set `executes_target = True` if the stage runs the binary — it will then be
   gated behind `--i-have-a-sandbox` automatically.
3. Implement `run(self, ctx) -> StageResult`. Return findings as `Finding`
   objects; **every finding that can carry a coordinate (address/offset/symbol)
   should**, so claims are reproducible.
4. Register the stage in `binscope/stages/__init__.py` (`REGISTRY`) and add it
   to the relevant set in `binscope/config.py`.
5. If it wraps a new tool, add a `_ToolSpec` to `binscope/tooling.py` with an
   install hint per platform.
6. Add a test under `tests/`.

## Scope and conduct

binscope is for **authorized** work only: malware defense, CTFs, security
research, interoperability, forensics, and debugging your own or a client's
software. Contributions that add DRM/license-bypass, game cheats, or
anti-detection/evasion features will not be accepted. See
[SECURITY.md](SECURITY.md) for reporting vulnerabilities in binscope itself.

## Commit / PR guidelines

- One logical change per PR; keep the diff focused.
- Write a test that fails before your fix and passes after.
- Describe *what* and *why* in the PR body, not just *how*.
