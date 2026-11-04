"""Stage: symbolic reachability with angr.

Two modes:
  * CFG mode (default): recover a fast CFG, report counts and unreachable-from-
    entry functions (candidate dormant/dead code or dynamically-reached code).
  * Reach mode (--angr-find ADDR): symbolically explore from the entry point to
    find an input that reaches ADDR, optionally avoiding --angr-avoid ADDRs,
    and report the concrete stdin that gets there.

angr is imported lazily so the rest of the pipeline works without it.
"""
from __future__ import annotations

from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from .base import Stage, StageContext


class AngrStage(Stage):
    name = "angr"
    tool = "angr"
    required_tool = "angr"

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        try:
            import angr  # noqa: F401
            import logging
            logging.getLogger("angr").setLevel(logging.ERROR)
            logging.getLogger("cle").setLevel(logging.ERROR)
            logging.getLogger("pyvex").setLevel(logging.ERROR)
        except Exception as exc:  # noqa: BLE001
            res.status = StageStatus.TOOL_MISSING
            res.summary = f"angr import failed: {exc}"
            return res

        import angr

        proj = angr.Project(str(ctx.target), auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        funcs = cfg.kb.functions
        n_funcs = len(funcs)

        # Functions not reachable from the entry in the static CFG. These are
        # prime candidates for dynamically-resolved / dormant code paths.
        entry_func = funcs.get(proj.entry)
        reachable = set()
        if entry_func is not None:
            stack = [entry_func.addr]
            callgraph = cfg.kb.functions.callgraph
            while stack:
                a = stack.pop()
                if a in reachable:
                    continue
                reachable.add(a)
                for succ in callgraph.successors(a) if a in callgraph else []:
                    stack.append(succ)
        unreachable = [f for a, f in funcs.items()
                       if a not in reachable and not f.is_simprocedure
                       and not f.is_plt]
        if unreachable:
            sample = ", ".join(sorted(
                (f.name or hex(f.addr)) for f in unreachable)[:15])
            res.add(Finding(
                title=f"{len(unreachable)} functions not statically reachable from entry",
                detail="Candidate dormant code or code reached only via indirect/"
                "dynamic calls (function pointers, dlsym, callbacks). Sample: " + sample,
                severity=Severity.MEDIUM, tags=["reachability", "dormant"],
                knowledge="inferred"))

        res.notes.append(f"CFG: {n_funcs} functions, {len(reachable)} reachable from entry")

        # Reach mode.
        if ctx.config.angr_find is not None:
            self._reach(proj, angr, ctx, res)

        res.summary = res.summary or f"{n_funcs} functions, {len(unreachable)} unreachable"
        if not res.findings:
            res.status = StageStatus.EMPTY
        return res

    def _reach(self, proj, angr, ctx: StageContext, res: StageResult) -> None:
        find = ctx.config.angr_find
        avoid = ctx.config.angr_avoid or []
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        steps = 0
        try:
            while simgr.active and steps < ctx.config.angr_max_steps:
                simgr.explore(find=find, avoid=avoid, n=1)
                steps += 1
                if simgr.found:
                    break
        except Exception as exc:  # noqa: BLE001
            res.notes.append(f"reach exploration error after {steps} steps: {exc}")

        if simgr.found:
            found = simgr.found[0]
            try:
                stdin_bytes = found.posix.dumps(0)
                evidence = repr(stdin_bytes[:200])
            except Exception:  # noqa: BLE001
                evidence = "<could not concretize stdin>"
            res.add(Finding(
                title=f"Reached 0x{find:x} symbolically",
                detail="An input exists that drives execution to the target address.",
                severity=Severity.HIGH, coordinate=f"0x{find:x}",
                evidence=f"stdin = {evidence}", tags=["reach", "symbolic"],
                knowledge="observed-runtime"))
        else:
            res.add(Finding(
                title=f"Did not reach 0x{find:x} within {ctx.config.angr_max_steps} steps",
                detail="Address may be unreachable, guarded by unmodeled state, or "
                "need a larger step budget / different avoid set.",
                severity=Severity.INFO, coordinate=f"0x{find:x}",
                tags=["reach"], knowledge="inferred"))
