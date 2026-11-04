"""Stage: coverage-guided fuzzing with AFL++. EXECUTES the target (Linux).

This drives a time-boxed `afl-fuzz` campaign against a target that reads input
from a file (the AFL `@@` placeholder) or stdin. It does NOT instrument/compile
the target — it assumes either an AFL-instrumented build or uses QEMU mode (-Q)
for black-box binaries. Crashes and hangs are reported with reproducer paths.

Gated behind --i-have-a-sandbox. For parser/input-driven dormant behaviour and
memory-safety bugs.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import run, which
from .base import Stage, StageContext


class AflStage(Stage):
    name = "fuzz"
    tool = "afl++"
    required_tool = "afl++"
    executes_target = True

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        afl = ctx.tools["afl++"].path or which("afl-fuzz")
        if not afl:
            res.status = StageStatus.TOOL_MISSING
            res.summary = "afl-fuzz not found (Linux only)"
            return res

        sdir = ctx.stage_dir(self.name)
        in_dir = ctx.config.fuzz_seed_dir or (sdir / "in")
        out_dir = sdir / "out"
        in_dir = Path(in_dir)
        in_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        # Minimal seed so AFL can start if the user gave none.
        if not any(in_dir.iterdir()):
            (in_dir / "seed0").write_bytes(b"0\n")

        # Black-box binary -> QEMU mode (-Q). Harmless if already instrumented.
        env = dict(os.environ)
        env.setdefault("AFL_SKIP_CPUFREQ", "1")
        env.setdefault("AFL_NO_AFFINITY", "1")
        env.setdefault("AFL_BENCH_UNTIL_CRASH", "0")

        target_args = ctx.config.fuzz_target_args.split()
        argv = [afl, "-Q", "-i", str(in_dir), "-o", str(out_dir),
                "-V", str(ctx.config.fuzz_duration),  # run for N seconds then exit
                "--", str(ctx.target)] + target_args

        rr = run(argv, timeout=ctx.config.fuzz_duration + 90, env=env)
        (sdir / "afl.log").write_text(rr.stdout + "\n" + rr.stderr, encoding="utf-8")

        crashes_dir = out_dir / "default" / "crashes"
        hangs_dir = out_dir / "default" / "hangs"
        crashes = _list_reproducers(crashes_dir)
        hangs = _list_reproducers(hangs_dir)

        if crashes:
            res.add(Finding(
                title=f"{len(crashes)} crashing input(s) found",
                detail="Coverage-guided fuzzing reached a crash. Triage with a "
                "debugger (gdb -batch) and ASAN build to classify exploitability.",
                severity=Severity.HIGH,
                evidence="\n".join(crashes[:10]),
                tags=["crash", "fuzz"], knowledge="observed-runtime"))
        if hangs:
            res.add(Finding(
                title=f"{len(hangs)} hang(s) found",
                severity=Severity.MEDIUM,
                evidence="\n".join(hangs[:10]),
                tags=["hang", "fuzz"], knowledge="observed-runtime"))

        res.artifacts.append(str(out_dir))
        res.summary = (f"{len(crashes)} crashes, {len(hangs)} hangs in "
                       f"{ctx.config.fuzz_duration}s")
        if not crashes and not hangs:
            res.status = StageStatus.EMPTY
            if "PROGRAM ABORT" in (rr.stdout + rr.stderr):
                res.status = StageStatus.FAILED
                res.summary = "afl-fuzz aborted at startup — check afl.log (QEMU mode / seeds / target args)."
        return res


def _list_reproducers(d: Path) -> list[str]:
    if not d.exists():
        return []
    return [str(p) for p in sorted(d.iterdir())
            if p.is_file() and p.name not in {"README.txt"}]
