"""Pipeline stages. Each stage is a callable returning a StageResult."""
from __future__ import annotations

from .base import Stage, StageContext
from . import triage, static_ghidra, static_rizin, capa_stage, angr_stage
from . import dynamic_frida, dynamic_systrace, fuzz_afl

# Map logical stage name -> Stage implementation.
REGISTRY: dict[str, Stage] = {
    "triage": triage.TriageStage(),
    "ghidra": static_ghidra.GhidraStage(),
    "rizin": static_rizin.RizinStage(),
    "capa": capa_stage.CapaStage(),
    "angr": angr_stage.AngrStage(),
    "frida": dynamic_frida.FridaStage(),
    "systrace": dynamic_systrace.SystraceStage(),
    "fuzz": fuzz_afl.AflStage(),
}

__all__ = ["Stage", "StageContext", "REGISTRY"]
