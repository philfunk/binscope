"""Unified report data model and renderers (JSON + Markdown)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class StageStatus(str, Enum):
    OK = "ok"                    # ran and produced results
    EMPTY = "empty"              # ran cleanly but found nothing
    SKIPPED = "skipped"          # intentionally not run (not requested / wrong platform)
    TOOL_MISSING = "tool_missing"  # required tool not installed
    FAILED = "failed"            # the tool errored
    REFUSED = "refused"          # execution stage blocked for safety


@dataclass
class Finding:
    """One observation. Every finding should carry a coordinate when it has one."""

    title: str
    detail: str = ""
    severity: Severity = Severity.INFO
    coordinate: str = ""          # address / offset / symbol / request #
    evidence: str = ""            # short captured snippet backing the claim
    tags: list[str] = field(default_factory=list)
    knowledge: str = "inferred"   # read / confirmed-asm / observed-runtime / inferred

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class StageResult:
    name: str
    tool: str
    status: StageStatus = StageStatus.SKIPPED
    summary: str = ""
    duration: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)  # paths to exported files
    notes: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "status": self.status.value,
            "summary": self.summary,
            "duration": round(self.duration, 3),
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": self.artifacts,
            "notes": self.notes,
        }


@dataclass
class TargetInfo:
    path: str
    size: int = 0
    sha256: str = ""
    filetype: str = "unknown"
    family: str = "unknown"
    arch: str = "unknown"
    bits: int = 0
    entropy: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    target: TargetInfo
    platform: str = ""
    binscope_version: str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    stages: list[StageResult] = field(default_factory=list)

    # --- aggregate helpers -------------------------------------------------
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for st in self.stages:
            out.extend(st.findings)
        return out

    def top_findings(self, limit: int = 25) -> list[tuple[str, Finding]]:
        pairs = [(st.name, f) for st in self.stages for f in st.findings]
        pairs.sort(key=lambda p: p[1].severity.rank, reverse=True)
        return pairs[:limit]

    # --- renderers ---------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "binscope_version": self.binscope_version,
            "generated_at": self.generated_at,
            "platform": self.platform,
            "target": self.target.to_dict(),
            "stages": [s.to_dict() for s in self.stages],
            "summary_counts": self._counts(),
        }

    def _counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings():
            counts[f.severity.value] += 1
        return counts

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        t = self.target
        counts = self._counts()
        lines: list[str] = []
        lines.append(f"# binscope report — `{Path(t.path).name}`")
        lines.append("")
        lines.append(f"- **Generated:** {self.generated_at}")
        lines.append(f"- **Analysis host:** {self.platform}")
        lines.append(f"- **File type:** {t.filetype} ({t.family}, {t.arch}/{t.bits}-bit)")
        lines.append(f"- **Size:** {t.size:,} bytes  |  **Entropy:** {t.entropy:.2f} bits/byte")
        lines.append(f"- **SHA-256:** `{t.sha256}`")
        lines.append("")
        lines.append(
            "**Findings:** "
            + ", ".join(f"{counts[s.value]} {s.value}" for s in reversed(list(Severity)))
        )
        lines.append("")

        # Stage status table
        lines.append("## Pipeline")
        lines.append("")
        lines.append("| Stage | Tool | Status | Findings | Time (s) | Summary |")
        lines.append("|---|---|---|---:|---:|---|")
        for st in self.stages:
            lines.append(
                f"| {st.name} | {st.tool} | {st.status.value} | {len(st.findings)} "
                f"| {st.duration:.1f} | {st.summary} |"
            )
        lines.append("")

        # Top findings
        top = self.top_findings()
        if top:
            lines.append("## Top findings")
            lines.append("")
            for stage_name, f in top:
                coord = f" `@{f.coordinate}`" if f.coordinate else ""
                lines.append(f"### [{f.severity.value.upper()}] {f.title}{coord}")
                lines.append(f"*stage: {stage_name} · basis: {f.knowledge}*")
                lines.append("")
                if f.detail:
                    lines.append(f.detail)
                    lines.append("")
                if f.evidence:
                    lines.append("```")
                    lines.append(f.evidence.strip())
                    lines.append("```")
                    lines.append("")
                if f.tags:
                    lines.append("tags: " + ", ".join(f"`{x}`" for x in f.tags))
                    lines.append("")

        # Per-stage detail
        lines.append("## Stage detail")
        lines.append("")
        for st in self.stages:
            lines.append(f"### {st.name} — {st.tool} ({st.status.value})")
            lines.append("")
            if st.summary:
                lines.append(st.summary)
                lines.append("")
            for note in st.notes:
                lines.append(f"- {note}")
            if st.notes:
                lines.append("")
            if st.artifacts:
                lines.append("Exported artifacts:")
                for a in st.artifacts:
                    lines.append(f"- `{a}`")
                lines.append("")

        lines.append("---")
        lines.append(
            "_Dynamic and fuzzing stages execute the target; only enable them "
            "inside a disposable, network-contained sandbox._"
        )
        return "\n".join(lines)

    def write(self, out_dir: Path, basename: str = "report") -> dict[str, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"{basename}.json"
        md_path = out_dir / f"{basename}.md"
        json_path.write_text(self.to_json(), encoding="utf-8")
        md_path.write_text(self.to_markdown(), encoding="utf-8")
        return {"json": json_path, "markdown": md_path}
