"""Stage: static analysis with Rizin (the engine behind Cutter).

Non-interactive `rizin -q -c '...'`. We pull the function list, imports,
exports, and flagged API usage, then turn notable items into findings.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import run
from .base import Stage, StageContext

# Import names that indicate capability, grouped by concern.
_CAP_IMPORTS = {
    "network": ["socket", "connect", "send", "recv", "InternetOpen", "WSAStartup",
                "URLDownloadToFile", "WinHttp", "getaddrinfo", "curl_easy"],
    "process-injection": ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
                          "NtMapViewOfSection", "QueueUserAPC", "SetThreadContext"],
    "persistence": ["RegSetValue", "RegCreateKey", "CreateService", "schtasks"],
    "crypto": ["CryptEncrypt", "CryptAcquireContext", "BCryptEncrypt", "EVP_EncryptInit"],
    "dynamic-load": ["LoadLibrary", "GetProcAddress", "dlopen", "dlsym"],
    "anti-analysis": ["IsDebuggerPresent", "CheckRemoteDebugger", "ptrace",
                      "NtQueryInformationProcess", "GetTickCount"],
}


class RizinStage(Stage):
    name = "rizin"
    tool = "rizin"
    required_tool = "rizin"

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        rizin = ctx.tools["rizin"].path or "rizin"
        sdir = ctx.stage_dir(self.name)

        # One batch session: analyze all, emit JSON for info/imports/functions.
        cmds = ";".join([
            "aaa",
            "ij",        # binary info (json)
            "iij",       # imports (json)
            "iEj",       # exports (json)
            "aflj",      # functions (json)
        ])
        rr = run([rizin, "-q", "-c", cmds, str(ctx.target)],
                 timeout=ctx.config.per_tool_timeout)
        raw_path = sdir / "rizin.out"
        raw_path.write_text(rr.stdout + "\n--stderr--\n" + rr.stderr, encoding="utf-8")
        res.artifacts.append(str(raw_path))

        if not rr.ok and not rr.stdout.strip():
            res.status = StageStatus.FAILED
            res.summary = f"rizin failed (rc={rr.returncode}): {rr.stderr[:200]}"
            return res

        info, imports, exports, funcs = _split_json_objects(rr.stdout)

        if info:
            bi = info.get("bin", {})
            ctx.target_info.arch = bi.get("arch", ctx.target_info.arch) or ctx.target_info.arch
            if bi.get("bits"):
                ctx.target_info.bits = bi["bits"]
            res.notes.append(
                f"bin: {bi.get('bintype','?')} {bi.get('arch','?')}/{bi.get('bits','?')} "
                f"os={bi.get('os','?')} canary={bi.get('canary')} nx={bi.get('nx')} "
                f"pic={bi.get('pic')} stripped={bi.get('stripped')}"
            )
            if bi.get("stripped"):
                res.add(Finding(
                    title="Binary is stripped",
                    detail="No symbol names; rely on xrefs, strings, and library calls.",
                    severity=Severity.INFO, tags=["toolchain"], knowledge="confirmed-asm"))
            if bi.get("nx") is False:
                res.add(Finding(title="NX disabled (executable stack/heap)",
                                severity=Severity.LOW, tags=["mitigations"],
                                knowledge="confirmed-asm"))

        import_names = [i.get("name", "") for i in (imports or [])]
        # Capability mapping from the import table (stronger than string match).
        for concern, needles in _CAP_IMPORTS.items():
            hits = sorted({n for n in import_names
                           for k in needles if k.lower() in n.lower()})
            if hits:
                sev = Severity.HIGH if concern == "process-injection" else Severity.MEDIUM
                res.add(Finding(
                    title=f"Imports suggest capability: {concern}",
                    detail="Imported symbols: " + ", ".join(hits[:12]),
                    severity=sev, tags=[concern, "imports"], knowledge="confirmed-asm"))

        if exports:
            names = [e.get("name", "") for e in exports][:40]
            res.notes.append(f"{len(exports)} exports (first: {', '.join(names[:8])})")

        if funcs:
            res.notes.append(f"{len(funcs)} functions recovered")
            # Largest functions are often the core logic; list a few as jump targets.
            big = sorted(funcs, key=lambda f: f.get("size", 0), reverse=True)[:5]
            for f in big:
                res.add(Finding(
                    title=f"Large function {f.get('name','?')} ({f.get('size',0)} bytes)",
                    detail="High-complexity routine; candidate for the core logic.",
                    severity=Severity.INFO,
                    coordinate=hex(f.get("offset", 0)),
                    tags=["function"], knowledge="confirmed-asm"))

        res.summary = (
            f"{len(import_names)} imports, {len(exports or [])} exports, "
            f"{len(funcs or [])} functions"
        )
        if not res.findings:
            res.status = StageStatus.EMPTY
        return res


def _split_json_objects(text: str):
    """Rizin prints several JSON values back-to-back. Decode them in order."""
    objs = []
    dec = json.JSONDecoder()
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            val, end = dec.raw_decode(text, idx)
            objs.append(val)
            idx = end
        except json.JSONDecodeError:
            idx += 1
    # Pad to 4 expected results (info, imports, exports, funcs).
    while len(objs) < 4:
        objs.append(None)
    return objs[0], objs[1], objs[2], objs[3]
