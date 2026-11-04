from binscope.config import Config
from binscope.report import Severity, StageStatus, TargetInfo
from binscope.stages.base import StageContext
from binscope.stages.triage import TriageStage
from binscope.util import sniff_filetype


def _ctx(sample, tmp_path):
    ft = sniff_filetype(sample)
    info = TargetInfo(path=str(sample), filetype=ft.label, family=ft.family,
                      arch=ft.arch, bits=ft.bits)
    cfg = Config(target=sample, out_dir=tmp_path / "out")
    return StageContext(config=cfg, target=sample, target_info=info,
                        tools={}, workdir=tmp_path / "work")


def test_triage_finds_markers(synthetic_sample, tmp_path):
    ctx = _ctx(synthetic_sample, tmp_path)
    res = TriageStage().run(ctx)

    assert res.status == StageStatus.OK
    titles = " | ".join(f.title for f in res.findings)
    assert "WriteProcessMemory" in titles
    assert "VirtualAlloc" in titles
    assert "IsDebuggerPresent" in titles
    assert "AES" in titles                     # crypto constant detected

    # The injection API should be the highest-severity triage finding.
    top = max(res.findings, key=lambda f: f.severity.rank)
    assert top.severity == Severity.HIGH
    assert "WriteProcessMemory" in top.title

    # Findings that located a byte offset must carry a coordinate.
    api = next(f for f in res.findings if "VirtualAlloc" in f.title)
    assert api.coordinate.startswith("0x")


def test_triage_writes_strings_artifact(synthetic_sample, tmp_path):
    ctx = _ctx(synthetic_sample, tmp_path)
    res = TriageStage().run(ctx)
    assert res.artifacts, "triage should export a strings dump"
    from pathlib import Path
    assert Path(res.artifacts[0]).exists()
