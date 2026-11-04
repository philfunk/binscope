import json

from binscope.report import (Finding, Report, Severity, StageResult,
                             StageStatus, TargetInfo)


def _report():
    st = StageResult(name="triage", tool="builtin", status=StageStatus.OK,
                     summary="demo")
    st.add(Finding(title="low thing", severity=Severity.LOW))
    st.add(Finding(title="scary thing", severity=Severity.HIGH,
                   coordinate="0x401000", detail="bad", tags=["injection"]))
    rep = Report(target=TargetInfo(path="x.bin", sha256="abc", filetype="ELF"),
                 platform="test", binscope_version="0.1.0")
    rep.stages.append(st)
    return rep


def test_counts_and_ordering():
    rep = _report()
    counts = rep._counts()
    assert counts["high"] == 1 and counts["low"] == 1
    top = rep.top_findings()
    assert top[0][1].severity == Severity.HIGH      # most severe first


def test_json_roundtrips():
    rep = _report()
    data = json.loads(rep.to_json())
    assert data["target"]["sha256"] == "abc"
    assert data["summary_counts"]["high"] == 1
    assert data["stages"][0]["findings"][1]["coordinate"] == "0x401000"


def test_markdown_contains_key_bits():
    md = _report().to_markdown()
    assert "# binscope report" in md
    assert "scary thing" in md
    assert "`@0x401000`" in md
    assert "| Stage | Tool | Status |" in md


def test_write_outputs(tmp_path):
    paths = _report().write(tmp_path, basename="r")
    assert paths["json"].exists() and paths["markdown"].exists()
    assert "binscope report" in paths["markdown"].read_text(encoding="utf-8")
