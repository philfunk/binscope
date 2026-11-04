---
name: Bug report
about: binscope crashed, mis-parsed a tool, or produced a wrong finding
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the problem.

**Stage / tool involved**
e.g. `rizin` stage, or the Markdown report renderer.

**To reproduce**
Command you ran (redact any real target path/name):

```
binscope analyze ... 
```

**Expected vs actual**
What you expected, and what binscope did instead.

**Environment**
- binscope version (`binscope --version`):
- OS:
- `binscope inventory` output (which tools are installed + versions):

**Logs / artifacts**
Attach the relevant file under `out/work/<stage>/` if you can share it. Do NOT
attach real customer data or live malware samples.
