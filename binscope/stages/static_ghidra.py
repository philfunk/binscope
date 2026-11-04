"""Stage: Ghidra headless decompilation export.

Drives `analyzeHeadless` with a bundled post-script that writes a header map
(entry points, imports, strings, most-called functions, and which functions
touch network/crypto/file/process/registry/dynamic-load APIs) followed by the
decompiled C. We parse the map for capability findings and keep the full C as
an artifact for slice-reading.

analyzeHeadless exits 0 even when the script fails, so we verify the export
file exists and ends with the expected trailer.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import run
from .base import Stage, StageContext

_RESOURCES = Path(__file__).resolve().parent.parent / "resources"
_TRAILER = "/* exported"

_CONCERN_SEV = {
    "process": Severity.HIGH,
    "network": Severity.MEDIUM,
    "crypto": Severity.MEDIUM,
    "registry": Severity.MEDIUM,
    "dynload": Severity.LOW,
    "file": Severity.LOW,
}


class GhidraStage(Stage):
    name = "ghidra"
    tool = "ghidra"
    required_tool = "ghidra"

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        headless = ctx.tools["ghidra"].path
        if not headless:
            res.status = StageStatus.TOOL_MISSING
            res.summary = "analyzeHeadless not located"
            return res

        sdir = ctx.stage_dir(self.name)
        proj = sdir / "ghproj"
        proj.mkdir(parents=True, exist_ok=True)
        export = sdir / "decomp.txt"
        script = _RESOURCES / "DecompileExport.java"

        argv = [
            headless, str(proj), "re",
            "-import", str(ctx.target),
            "-scriptPath", str(_RESOURCES),
            "-postScript", "DecompileExport.java", str(export),
        ]
        if ctx.config.func_filter:
            argv.append(ctx.config.func_filter)
            if ctx.config.max_functions:
                argv.append(str(ctx.config.max_functions))
        argv += ["-analysisTimeoutPerFile", str(ctx.config.ghidra_timeout),
                 "-deleteProject"]

        rr = run(argv, timeout=ctx.config.ghidra_timeout + 120)
        (sdir / "headless.log").write_text(rr.stdout + "\n" + rr.stderr, encoding="utf-8")

        if not export.exists():
            res.status = StageStatus.FAILED
            res.summary = ("Ghidra produced no export (script may have failed; "
                           "check headless.log). Needs JDK 21.")
            return res

        text = export.read_text(encoding="utf-8", errors="replace")
        if _TRAILER not in text:
            res.status = StageStatus.FAILED
            res.summary = "Export truncated (no trailer) — analysis likely timed out."
            res.artifacts.append(str(export))
            return res

        res.artifacts.append(str(export))
        self._parse_map(text, res)
        res.summary = (res.summary or "decompiled C exported") + f" ({len(text):,} bytes)"
        if not res.findings:
            res.status = StageStatus.EMPTY
        return res

    def _parse_map(self, text: str, res: StageResult) -> None:
        """Read the header map the post-script emits as `#MAP key: values`."""
        n_funcs = 0
        for line in text.splitlines():
            if not line.startswith("#MAP "):
                if line.startswith("/* exported"):
                    # "/* exported N functions */"
                    parts = line.split()
                    if len(parts) >= 3 and parts[2].isdigit():
                        n_funcs = int(parts[2])
                continue
            body = line[len("#MAP "):]
            if ":" not in body:
                continue
            key, _, vals = body.partition(":")
            key = key.strip().lower()
            items = [v.strip() for v in vals.split(",") if v.strip()]
            if not items:
                continue
            if key in _CONCERN_SEV:
                res.add(Finding(
                    title=f"Functions using {key} APIs: {len(items)}",
                    detail="Start reading here. Functions: " + ", ".join(items[:12]),
                    severity=_CONCERN_SEV[key],
                    tags=[key, "ghidra-map"], knowledge="read"))
            elif key == "entry":
                res.add(Finding(title=f"Entry points: {', '.join(items[:6])}",
                                severity=Severity.INFO, tags=["entry"],
                                knowledge="confirmed-asm"))
            elif key == "mostcalled":
                res.add(Finding(
                    title="Most-called functions (name these first)",
                    detail=", ".join(items[:15]),
                    severity=Severity.INFO, tags=["hotspots"], knowledge="confirmed-asm"))
        if n_funcs:
            res.summary = f"{n_funcs} functions decompiled"
