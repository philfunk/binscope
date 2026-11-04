"""Stage: syscall / library-call tracing with strace + ltrace (Linux).

EXECUTES the target. Gated behind --i-have-a-sandbox. A lightweight companion
to the Frida stage: no scripting, just the kernel/library boundary.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import run, which
from .base import Stage, StageContext

# Syscalls worth calling out when observed.
_NOTABLE = {
    "connect": ("network", Severity.HIGH),
    "sendto": ("network", Severity.MEDIUM),
    "execve": ("exec", Severity.HIGH),
    "ptrace": ("anti-analysis", Severity.MEDIUM),
    "open": ("file", Severity.LOW),
    "openat": ("file", Severity.LOW),
    "unlink": ("file", Severity.MEDIUM),
    "mprotect": ("memory", Severity.MEDIUM),
    "clone": ("process", Severity.LOW),
}
_SYSCALL_RE = re.compile(r"^(\w+)\(")


class SystraceStage(Stage):
    name = "systrace"
    tool = "strace/ltrace"
    required_tool = None  # checked manually (needs at least one)
    executes_target = True

    def available(self, ctx: StageContext):
        if which("strace") or which("ltrace"):
            return True, ""
        return False, "neither strace nor ltrace installed (Linux only)"

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        sdir = ctx.stage_dir(self.name)
        strace = which("strace")
        ltrace = which("ltrace")

        if strace:
            trace_path = sdir / "strace.log"
            # -f follow forks, -tt timestamps, -o to file; bounded by `timeout`.
            argv = [strace, "-f", "-tt", "-o", str(trace_path), str(ctx.target)]
            rr = run(argv, timeout=ctx.config.frida_duration + 30)
            res.artifacts.append(str(trace_path))
            if trace_path.exists():
                self._summarise_strace(trace_path, res)
            else:
                res.notes.append(f"strace produced no log: {rr.stderr[:160]}")

        if ltrace:
            lt_path = sdir / "ltrace.log"
            rr = run([ltrace, "-f", "-o", str(lt_path), str(ctx.target)],
                     timeout=ctx.config.frida_duration + 30)
            if lt_path.exists():
                res.artifacts.append(str(lt_path))
                res.notes.append(f"ltrace log: {lt_path.name}")

        res.summary = res.summary or "tracing complete"
        if not res.findings:
            res.status = StageStatus.EMPTY
        return res

    def _summarise_strace(self, path: Path, res: StageResult) -> None:
        counts: Counter = Counter()
        notable_hits: dict[str, list[str]] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            # Lines look like: "1234 12:00:00.000 connect(3, {...}) = 0"
            m = _SYSCALL_RE.search(line.split(None, 2)[-1] if line else "")
            if not m:
                # try without pid/timestamp prefix
                m = _SYSCALL_RE.search(line.strip())
            if not m:
                continue
            sc = m.group(1)
            counts[sc] += 1
            if sc in _NOTABLE:
                notable_hits.setdefault(sc, []).append(line.strip()[:160])

        for sc, lines in notable_hits.items():
            cat, sev = _NOTABLE[sc]
            res.add(Finding(
                title=f"syscall {sc} x{counts[sc]} ({cat})",
                detail="Observed during execution.",
                severity=sev, evidence="\n".join(lines[:5]),
                tags=[cat, "syscall", "runtime"], knowledge="observed-runtime"))
        if counts:
            top = ", ".join(f"{k}:{v}" for k, v in counts.most_common(10))
            res.notes.append(f"top syscalls: {top}")
