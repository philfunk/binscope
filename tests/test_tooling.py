from binscope.config import ALL_STAGES, EXECUTION_STAGES, STATIC_STAGES
from binscope.tooling import detect, detect_all


EXPECTED = {"ghidra", "rizin", "capa", "angr", "frida", "afl++", "strace", "ltrace"}


def test_detect_all_structure():
    statuses = detect_all()
    assert EXPECTED.issubset(set(statuses))
    for st in statuses.values():
        assert isinstance(st.present, bool)
        # A missing tool must advertise how to install it.
        if not st.present:
            assert st.install_hint != ""


def test_detect_unknown_tool():
    st = detect("does-not-exist")
    assert st.present is False


def test_stage_sets_consistent():
    # Static set never contains an execution stage.
    assert set(STATIC_STAGES).isdisjoint(EXECUTION_STAGES)
    # Every configured stage is a known stage.
    for s in STATIC_STAGES + list(EXECUTION_STAGES):
        assert s in ALL_STAGES
