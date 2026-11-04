"""Command-line interface for binscope.

    binscope inventory
    binscope analyze <target> [options]

`analyze` runs the pipeline and writes report.json + report.md into the output
directory. Static stages are the default; execution stages (frida/systrace/
fuzz) require --i-have-a-sandbox.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config, ALL_STAGES, STATIC_STAGES, EXECUTION_STAGES
from .pipeline import Pipeline
from .tooling import detect_all, render_inventory
from .util import eprint


def _parse_int_maybe_hex(s: str) -> int:
    return int(s, 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="binscope",
        description="Reverse-engineering + dynamic-analysis orchestrator "
        "(Ghidra, Rizin, capa, angr, Frida, AFL++).",
    )
    p.add_argument("--version", action="version", version=f"binscope {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # inventory
    sub.add_parser("inventory", help="Show which analysis tools are installed.")

    # analyze
    a = sub.add_parser("analyze", help="Run the analysis pipeline on a target.")
    a.add_argument("target", type=Path, help="Path to the binary to analyze.")
    a.add_argument("-o", "--out", type=Path, default=Path("binscope-out"),
                   help="Output directory (default: ./binscope-out).")
    a.add_argument("--stages", default=",".join(STATIC_STAGES),
                   help="Comma-separated stage list. Options: "
                   + ",".join(ALL_STAGES) + ". Use 'all' for everything. "
                   "Default: static only.")
    a.add_argument("--i-have-a-sandbox", action="store_true", dest="allow_execution",
                   help="Confirm you are in a disposable, network-contained "
                   "environment; required to run execution stages "
                   "(frida/systrace/fuzz).")
    a.add_argument("--dry-run", action="store_true",
                   help="Print the plan (what will run / be skipped) and exit.")
    a.add_argument("-v", "--verbose", action="store_true")

    # budgets
    a.add_argument("--timeout", type=int, default=900,
                   help="Per-tool timeout in seconds (default 900).")
    a.add_argument("--ghidra-timeout", type=int, default=900)
    a.add_argument("--max-functions", type=int, default=0,
                   help="Cap Ghidra decompiled functions (0 = no cap).")
    a.add_argument("--func-filter", default="",
                   help="Case-insensitive name filter for Ghidra decompile.")

    # angr
    a.add_argument("--angr-find", type=_parse_int_maybe_hex, default=None,
                   help="Address angr should try to reach (hex ok, e.g. 0x401abc).")
    a.add_argument("--angr-avoid", default="",
                   help="Comma-separated addresses angr should avoid.")

    # frida / fuzz budgets
    a.add_argument("--frida-duration", type=int, default=20)
    a.add_argument("--frida-pid", type=int, default=None,
                   help="Attach to a running PID instead of spawning the target.")
    a.add_argument("--frida-script", type=Path, default=None,
                   help="Custom Frida .js (default: bundled tracer).")
    a.add_argument("--fuzz-duration", type=int, default=120)
    a.add_argument("--fuzz-seeds", type=Path, default=None,
                   help="Directory of seed inputs for AFL++.")
    a.add_argument("--fuzz-args", default="@@",
                   help="Target args for fuzzing; @@ = input file (default '@@').")
    return p


def _resolve_stages(spec: str) -> list[str]:
    if spec.strip().lower() == "all":
        return list(ALL_STAGES)
    out = []
    for s in spec.split(","):
        s = s.strip().lower()
        if not s:
            continue
        if s not in ALL_STAGES:
            raise SystemExit(f"unknown stage '{s}'. valid: {', '.join(ALL_STAGES)}")
        out.append(s)
    return out


def cmd_inventory() -> int:
    print(render_inventory(detect_all()))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    target: Path = args.target
    if not target.exists() or not target.is_file():
        eprint(f"error: target not found or not a file: {target}")
        return 2

    stages = _resolve_stages(args.stages)
    avoid = [int(x, 0) for x in args.angr_avoid.split(",") if x.strip()]

    cfg = Config(
        target=target,
        out_dir=args.out,
        stages=stages,
        allow_execution=args.allow_execution,
        per_tool_timeout=args.timeout,
        ghidra_timeout=args.ghidra_timeout,
        max_functions=args.max_functions,
        func_filter=args.func_filter,
        angr_find=args.angr_find,
        angr_avoid=avoid,
        frida_duration=args.frida_duration,
        frida_pid=args.frida_pid,
        frida_spawn=args.frida_pid is None,
        frida_script=args.frida_script,
        fuzz_duration=args.fuzz_duration,
        fuzz_seed_dir=args.fuzz_seeds,
        fuzz_target_args=args.fuzz_args,
        verbose=args.verbose,
    )

    pipeline = Pipeline(cfg)

    # Warn loudly if execution stages were requested without the sandbox flag.
    requested_exec = [s for s in stages if s in EXECUTION_STAGES]
    if requested_exec and not cfg.allow_execution:
        eprint("[binscope] NOTE: execution stages requested "
               f"({', '.join(requested_exec)}) but --i-have-a-sandbox not set; "
               "they will be refused. Static stages still run.")

    if args.dry_run:
        print(pipeline.plan_summary())
        return 0

    report = pipeline.run()
    paths = report.write(cfg.out_dir)

    # Console summary.
    counts = report._counts()
    print(f"\nbinscope {__version__} - {target.name}")
    print(f"  {report.target.filetype} ({report.target.family}, "
          f"{report.target.arch}/{report.target.bits}-bit), "
          f"entropy {report.target.entropy:.2f}")
    print(f"  SHA-256 {report.target.sha256}")
    print("  stages: " + ", ".join(
        f"{s.name}={s.status.value}" for s in report.stages))
    print("  findings: " + ", ".join(
        f"{k}={v}" for k, v in counts.items() if v))
    print(f"\n  report: {paths['markdown']}")
    print(f"          {paths['json']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inventory":
        return cmd_inventory()
    if args.command == "analyze":
        return cmd_analyze(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
