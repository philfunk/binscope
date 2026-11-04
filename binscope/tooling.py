"""Detection of the external tools binscope orchestrates.

Each tool has a probe (how to find it) and an install hint per platform. The
pipeline consults this registry so it can plan around what is actually present
and tell the user exactly what to install for the stages they asked for.
"""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .util import run, which


@dataclass
class ToolStatus:
    name: str
    present: bool
    path: Optional[str] = None
    version: str = ""
    detail: str = ""
    install_hint: str = ""


def _ghidra_headless() -> Optional[str]:
    """Find analyzeHeadless via GHIDRA_INSTALL_DIR or PATH."""
    exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_dir:
        cand = Path(env_dir) / "support" / exe
        if cand.exists():
            return str(cand)
    found = which(exe) or which("analyzeHeadless")
    return found


def _probe_version(argv: list[str], *, timeout: float = 20.0) -> str:
    res = run(argv, timeout=timeout)
    text = (res.stdout or res.stderr).strip()
    return text.splitlines()[0][:120] if text else ""


# Registry: name -> (locator, version_probe, install hints per platform)
_PLATFORM = platform.system()  # 'Windows' / 'Linux' / 'Darwin'


@dataclass
class _ToolSpec:
    name: str
    locator: Callable[[], Optional[str]]
    version_argv: Optional[list[str]] = None
    hints: dict[str, str] = field(default_factory=dict)
    note: str = ""

    def hint(self) -> str:
        return self.hints.get(_PLATFORM, self.hints.get("*", ""))


_SPECS: list[_ToolSpec] = [
    _ToolSpec(
        name="ghidra",
        locator=_ghidra_headless,
        hints={
            "*": "Download from https://ghidra-sre.org, unzip, set "
            "GHIDRA_INSTALL_DIR. Needs JDK 21.",
            "Linux": "Install JDK 21 then unzip Ghidra; export GHIDRA_INSTALL_DIR=/opt/ghidra",
        },
        note="Static decompilation to C via analyzeHeadless (batch).",
    ),
    _ToolSpec(
        name="rizin",
        locator=lambda: which("rizin"),
        version_argv=["rizin", "-v"],
        hints={
            "Linux": "sudo apt install rizin  (or build from github.com/rizinorg/rizin)",
            "Darwin": "brew install rizin",
            "Windows": "Download installer from github.com/rizinorg/rizin/releases",
        },
        note="Fast static triage: functions, strings, imports, xrefs. Cutter is its GUI.",
    ),
    _ToolSpec(
        name="capa",
        locator=lambda: which("capa"),
        version_argv=["capa", "--version"],
        hints={"*": "pipx install flare-capa   (or: pip install flare-capa)"},
        note="Maps a binary to MITRE ATT&CK / MBC capabilities from code patterns.",
    ),
    _ToolSpec(
        name="angr",
        locator=lambda: _python_module("angr"),
        hints={"*": "pip install angr   (symbolic execution engine)"},
        note="Symbolic execution: which inputs reach a chosen address/branch.",
    ),
    _ToolSpec(
        name="frida",
        locator=lambda: which("frida") or which("frida-trace"),
        version_argv=["frida", "--version"],
        hints={"*": "pip install frida-tools"},
        note="Dynamic instrumentation: hook and log calls at runtime. EXECUTES target.",
    ),
    _ToolSpec(
        name="afl++",
        locator=lambda: which("afl-fuzz"),
        version_argv=["afl-fuzz", "-h"],
        hints={
            "Linux": "sudo apt install afl++  (or build AFLplusplus from source)",
            "*": "Linux only. Build github.com/AFLplusplus/AFLplusplus",
        },
        note="Coverage-guided fuzzing for crashes / input-driven hidden paths. EXECUTES target.",
    ),
    _ToolSpec(
        name="strace",
        locator=lambda: which("strace"),
        hints={"Linux": "sudo apt install strace",
               "*": "Linux only (e.g. `apt install strace`); unavailable on this OS."},
        note="Syscall tracer (Linux). EXECUTES target.",
    ),
    _ToolSpec(
        name="ltrace",
        locator=lambda: which("ltrace"),
        hints={"Linux": "sudo apt install ltrace",
               "*": "Linux only (e.g. `apt install ltrace`); unavailable on this OS."},
        note="Library-call tracer (Linux). EXECUTES target.",
    ),
]


def _python_module(mod: str) -> Optional[str]:
    import importlib.util

    spec = importlib.util.find_spec(mod)
    return mod if spec is not None else None


def detect(name: str) -> ToolStatus:
    spec = next((s for s in _SPECS if s.name == name), None)
    if spec is None:
        return ToolStatus(name=name, present=False, detail="unknown tool")
    path = spec.locator()
    present = path is not None
    version = ""
    if present and spec.version_argv and spec.name != "afl++":
        version = _probe_version(spec.version_argv)
    return ToolStatus(
        name=name,
        present=present,
        path=path,
        version=version,
        detail=spec.note,
        install_hint="" if present else spec.hint(),
    )


def detect_all() -> dict[str, ToolStatus]:
    return {spec.name: detect(spec.name) for spec in _SPECS}


def platform_name() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def render_inventory(statuses: dict[str, ToolStatus]) -> str:
    lines = [f"Analysis host: {platform_name()}", ""]
    for name, st in statuses.items():
        mark = "OK " if st.present else "-- "
        extra = st.version or st.path or ""
        lines.append(f"[{mark}] {name:<8} {extra}")
        if not st.present and st.install_hint:
            lines.append(f"          install: {st.install_hint}")
    return "\n".join(lines)
