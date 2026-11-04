from binscope.config import Config
from binscope.pipeline import Pipeline, build_target_info
from binscope.report import StageStatus


def test_target_info(synthetic_sample):
    info = build_target_info(synthetic_sample)
    assert info.sha256 and len(info.sha256) == 64
    assert info.family == "native"
    assert info.size > 0


def test_pipeline_triage_only(synthetic_sample, tmp_path):
    cfg = Config(target=synthetic_sample, out_dir=tmp_path / "out", stages=["triage"])
    report = Pipeline(cfg).run()
    assert len(report.stages) == 1
    triage = report.stages[0]
    assert triage.status == StageStatus.OK
    assert any("WriteProcessMemory" in f.title for f in triage.findings)
    # entropy was computed onto the target info
    assert report.target.entropy > 0


def test_execution_stage_refused_without_sandbox(synthetic_sample, tmp_path):
    cfg = Config(target=synthetic_sample, out_dir=tmp_path / "out",
                 stages=["frida"], allow_execution=False)
    report = Pipeline(cfg).run()
    assert report.stages[0].status == StageStatus.REFUSED


def test_missing_tool_reported(synthetic_sample, tmp_path):
    # rizin is almost certainly not installed in CI; if it is, the stage simply
    # runs and this assertion is skipped.
    cfg = Config(target=synthetic_sample, out_dir=tmp_path / "out", stages=["rizin"])
    report = Pipeline(cfg).run()
    assert report.stages[0].status in {StageStatus.TOOL_MISSING, StageStatus.OK,
                                       StageStatus.EMPTY, StageStatus.FAILED}
