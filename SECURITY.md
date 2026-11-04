# Security Policy

## Reporting a vulnerability

If you find a security issue **in binscope itself** (for example, a crafted
sample or tool output that leads binscope to execute attacker-controlled code
on the analyst's machine), please report it privately rather than opening a
public issue:

- Use GitHub's **"Report a vulnerability"** button under the repository's
  *Security* tab (Private Vulnerability Reporting), or
- Open a minimal public issue asking a maintainer to open a private channel,
  without details.

Please include: binscope version, OS, the stage involved, and the smallest
input that reproduces the problem. We aim to acknowledge reports within a few
days.

## Threat model

binscope analyzes **untrusted binaries**. It is designed so that static stages
never execute the target, and execution stages (`frida`, `systrace`, `fuzz`)
refuse to run without `--i-have-a-sandbox`. Even so, parsing hostile input is
inherently risky. Treat the machine running binscope as potentially exposed and
prefer a disposable, network-contained VM for any execution stage.

Text found inside a target (strings, decompiled code, tool output) is reported
as **data**. binscope never executes or acts on instructions embedded in a
sample. If you extend binscope, preserve that boundary.

## Out of scope

- Vulnerabilities in the external tools binscope wraps (report those upstream
  to Ghidra, Rizin, capa, angr, Frida, or AFL++).
- Misuse of binscope against systems you are not authorized to analyze.
