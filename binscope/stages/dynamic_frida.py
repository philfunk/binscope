"""Stage: dynamic instrumentation with Frida. EXECUTES the target.

Spawns (or attaches to) the target under a bundled tracer script that logs
network, file, process, crypto, and dynamic-loading calls, runs for a bounded
duration, then summarises what was actually invoked at runtime.

Gated behind --i-have-a-sandbox because it runs the binary.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import run
from .base import Stage, StageContext

_RESOURCES = Path(__file__).resolve().parent.parent / "resources"


class FridaStage(Stage):
    name = "frida"
    tool = "frida"
    required_tool = "frida"
    executes_target = True

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        frida = ctx.tools["frida"].path or "frida"
        sdir = ctx.stage_dir(self.name)
        script = ctx.config.frida_script or (_RESOURCES / "frida_trace.js")
        log_path = sdir / "frida.log"

        # frida CLI: -f spawn file, -l load script, -q quiet, -t timeout (s),
        # -o output file for console.log from the script.
        argv = [frida, "-q", "-l", str(script), "-o", str(log_path),
                "-t", str(ctx.config.frida_duration)]
        if ctx.config.frida_pid and not ctx.config.frida_spawn:
            argv += ["-p", str(ctx.config.frida_pid)]
        else:
            argv += ["-f", str(ctx.target)]

        rr = run(argv, timeout=ctx.config.frida_duration + 60)
        res.artifacts.append(str(log_path))
        if rr.stdout or rr.stderr:
            (sdir / "frida.console").write_text(rr.stdout + "\n" + rr.stderr,
                                                encoding="utf-8")

        if not log_path.exists():
            res.status = StageStatus.FAILED
            res.summary = f"Frida produced no log (rc={rr.returncode}): {rr.stderr[:200]}"
            return res

        events = self._parse_log(log_path)
        self._summarise(events, res)
        res.summary = res.summary or f"{len(events)} runtime events captured"
        if not events:
            res.status = StageStatus.EMPTY
        return res

    def _parse_log(self, log_path: Path) -> list[dict]:
        events = []
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def _summarise(self, events: list[dict], res: StageResult) -> None:
        by_cat: dict[str, list[dict]] = {}
        for ev in events:
            by_cat.setdefault(ev.get("cat", "misc"), []).append(ev)
        sev_map = {"network": Severity.HIGH, "process": Severity.HIGH,
                   "file": Severity.MEDIUM, "crypto": Severity.MEDIUM,
                   "loader": Severity.LOW, "registry": Severity.MEDIUM}
        for cat, evs in by_cat.items():
            samples = []
            for e in evs[:8]:
                samples.append(f"{e.get('api','?')}({e.get('arg','')[:60]})")
            res.add(Finding(
                title=f"Runtime {cat} activity: {len(evs)} calls",
                detail="Observed while executing the target.",
                severity=sev_map.get(cat, Severity.INFO),
                evidence="\n".join(samples),
                tags=[cat, "runtime"], knowledge="observed-runtime"))
