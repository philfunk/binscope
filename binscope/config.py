"""Run configuration: the knobs the pipeline reads."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Stages that run the target. Gated behind --i-have-a-sandbox.
EXECUTION_STAGES = {"frida", "systrace", "fuzz"}

# Logical stage names in pipeline order.
ALL_STAGES = ["triage", "ghidra", "rizin", "capa", "angr", "frida", "systrace", "fuzz"]

# Default "safe" set: static analysis only, never executes the target.
STATIC_STAGES = ["triage", "ghidra", "rizin", "capa", "angr"]


@dataclass
class Config:
    target: Path
    out_dir: Path
    stages: list[str] = field(default_factory=lambda: list(STATIC_STAGES))

    # safety / execution
    allow_execution: bool = False   # must be True for EXECUTION_STAGES to run

    # budgets
    per_tool_timeout: int = 900      # seconds for a single external tool
    ghidra_timeout: int = 900
    max_functions: int = 0           # 0 = no cap on Ghidra decompile export
    func_filter: str = ""            # case-insensitive name filter for Ghidra

    # angr
    angr_find: Optional[int] = None  # address to try to reach
    angr_avoid: list[int] = field(default_factory=list)
    angr_max_steps: int = 2000

    # frida
    frida_spawn: bool = True         # spawn (vs attach by pid)
    frida_pid: Optional[int] = None
    frida_duration: int = 20
    frida_script: Optional[Path] = None  # custom .js; default = bundled tracer

    # fuzz
    fuzz_seed_dir: Optional[Path] = None
    fuzz_duration: int = 120
    fuzz_target_args: str = "@@"     # AFL input placeholder

    # misc
    ghidra_dir: Optional[str] = None
    verbose: bool = False

    def wants(self, stage: str) -> bool:
        return stage in self.stages

    def execution_requested(self) -> list[str]:
        return [s for s in self.stages if s in EXECUTION_STAGES]
