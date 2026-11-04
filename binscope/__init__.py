"""binscope - a reverse-engineering and dynamic-analysis orchestrator.

binscope drives a suite of open-source binary-analysis tools (Ghidra, Rizin/
Cutter, capa, angr, Frida, AFL++, and native tracers) through a single staged
pipeline and merges everything into one unified report.

The pipeline follows the standard triage-first, static-before-dynamic method:

    triage  ->  static (Ghidra + Rizin)  ->  capabilities (capa)
            ->  reachability (angr)  ->  dynamic (Frida / strace-ltrace)
            ->  fuzzing (AFL++)

Stages that *execute* the target (dynamic, fuzz) are opt-in and refuse to run
without explicit acknowledgement, because running an untrusted binary is only
safe inside a disposable, network-contained sandbox.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
