"""The orchestrator: plan the run, execute stages in order, build the report."""
from __future__ import annotations

from pathlib import Path

from .config import Config, EXECUTION_STAGES
from .report import Report, StageResult, StageStatus, TargetInfo
from .tooling import ToolStatus, detect_all, platform_name
from .util import eprint, sha256_file, sniff_filetype
from . import __version__
from .stages import REGISTRY, StageContext


def build_target_info(target: Path) -> TargetInfo:
    ft = sniff_filetype(target)
    return TargetInfo(
        path=str(target),
        size=target.stat().st_size,
        sha256=sha256_file(target),
        filetype=ft.label,
        family=ft.family,
        arch=ft.arch,
        bits=ft.bits,
    )


class Pipeline:
    def __init__(self, config: Config, tools: dict[str, ToolStatus] | None = None):
        self.config = config
        self.tools = tools if tools is not None else detect_all()

    def run(self) -> Report:
        cfg = self.config
        target = cfg.target
        info = build_target_info(target)
        report = Report(
            target=info,
            platform=platform_name(),
            binscope_version=__version__,
        )

        workdir = cfg.out_dir / "work"
        workdir.mkdir(parents=True, exist_ok=True)
        ctx = StageContext(
            config=cfg, target=target, target_info=info,
            tools=self.tools, workdir=workdir,
        )

        for stage_name in cfg.stages:
            stage = REGISTRY.get(stage_name)
            if stage is None:
                eprint(f"[binscope] unknown stage: {stage_name}; skipping")
                continue
            if cfg.verbose:
                eprint(f"[binscope] running stage: {stage_name}")
            result = stage.execute(ctx)
            if cfg.verbose:
                eprint(f"[binscope]   -> {result.status.value}: {result.summary}")
            report.stages.append(result)

        return report

    def plan_summary(self) -> str:
        """Human-readable preview of what will run and what will be skipped."""
        lines = [f"Target: {self.config.target}", "Planned stages:"]
        for name in self.config.stages:
            stage = REGISTRY.get(name)
            if stage is None:
                lines.append(f"  - {name}: UNKNOWN")
                continue
            ok, reason = stage.available(StageContext(
                config=self.config, target=self.config.target,
                target_info=TargetInfo(path=str(self.config.target)),
                tools=self.tools, workdir=self.config.out_dir))
            if name in EXECUTION_STAGES and not self.config.allow_execution:
                status = "will REFUSE (execution; needs --i-have-a-sandbox)"
            elif ok:
                status = "ready"
            else:
                status = f"will skip ({reason})"
            lines.append(f"  - {name}: {status}")
        return "\n".join(lines)
