"""Stage protocol and shared execution context."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import Config
from ..report import StageResult, StageStatus, TargetInfo
from ..tooling import ToolStatus


@dataclass
class StageContext:
    """Everything a stage needs: config, target facts, tool inventory, workdir."""

    config: Config
    target: Path
    target_info: TargetInfo
    tools: dict[str, ToolStatus]
    workdir: Path                       # per-stage scratch output root
    shared: dict = field(default_factory=dict)  # cross-stage handoff (e.g. ghidra export path)

    def stage_dir(self, name: str) -> Path:
        d = self.workdir / name
        d.mkdir(parents=True, exist_ok=True)
        return d


class Stage:
    """Base class. Subclasses set `name`/`tool`/`required_tool` and implement run()."""

    name: str = "stage"
    tool: str = ""
    required_tool: Optional[str] = None  # key in the tool inventory
    executes_target: bool = False

    def available(self, ctx: StageContext) -> tuple[bool, str]:
        """Return (ok, reason). Default: required tool must be present."""
        if self.required_tool is None:
            return True, ""
        st = ctx.tools.get(self.required_tool)
        if st and st.present:
            return True, ""
        hint = st.install_hint if st else ""
        return False, f"{self.required_tool} not installed. {hint}".strip()

    def run(self, ctx: StageContext) -> StageResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # Wrapper that enforces safety + timing + tool presence uniformly.
    def execute(self, ctx: StageContext) -> StageResult:
        result = StageResult(name=self.name, tool=self.tool)
        start = time.monotonic()

        if self.executes_target and not ctx.config.allow_execution:
            result.status = StageStatus.REFUSED
            result.summary = (
                "Refused: this stage runs the target. Re-run with "
                "--i-have-a-sandbox to confirm you are in a disposable, "
                "network-contained environment."
            )
            result.duration = time.monotonic() - start
            return result

        ok, reason = self.available(ctx)
        if not ok:
            result.status = StageStatus.TOOL_MISSING
            result.summary = reason
            result.duration = time.monotonic() - start
            return result

        try:
            result = self.run(ctx)
        except Exception as exc:  # noqa: BLE001 - stages must never crash the pipeline
            result.status = StageStatus.FAILED
            result.summary = f"{type(exc).__name__}: {exc}"
        result.duration = time.monotonic() - start
        return result
