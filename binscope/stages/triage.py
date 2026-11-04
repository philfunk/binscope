"""Stage 1: triage. Cheapest wins — hashes, entropy, strings, obvious markers.

Runs with no external tools; pure stdlib so it always produces something.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import shannon_entropy
from .base import Stage, StageContext

# Interesting string patterns -> (regex, severity, tag).
_PATTERNS: list[tuple[str, re.Pattern, Severity, str]] = [
    ("url", re.compile(rb"https?://[\w\-./:%?=&@#]+"), Severity.LOW, "network"),
    ("ipv4", re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"), Severity.LOW, "network"),
    ("onion", re.compile(rb"\b[a-z2-7]{16,56}\.onion\b"), Severity.MEDIUM, "network"),
    ("email", re.compile(rb"[\w.\-]+@[\w\-]+\.[a-z]{2,}"), Severity.INFO, "contact"),
    ("regkey", re.compile(rb"(?i)(HKLM|HKCU|SOFTWARE\\|CurrentVersion\\Run)[\w\\]*"), Severity.MEDIUM, "persistence"),
    ("pdb", re.compile(rb"[A-Za-z]:\\[^\0\n]{0,120}\.pdb"), Severity.INFO, "toolchain"),
    ("cmd", re.compile(rb"(?i)\b(cmd\.exe|powershell|/bin/sh|/bin/bash|rundll32|regsvr32)\b"), Severity.MEDIUM, "exec"),
]

# API / symbol names that hint at capability even as bare strings.
_SUSPICIOUS_APIS = {
    b"VirtualAlloc": ("alloc-rwx", Severity.MEDIUM, "injection"),
    b"WriteProcessMemory": ("process-write", Severity.HIGH, "injection"),
    b"CreateRemoteThread": ("remote-thread", Severity.HIGH, "injection"),
    b"SetWindowsHookEx": ("hook", Severity.MEDIUM, "hooking"),
    b"InternetOpen": ("wininet", Severity.LOW, "network"),
    b"WSASocket": ("winsock", Severity.LOW, "network"),
    b"CryptEncrypt": ("crypto", Severity.MEDIUM, "crypto"),
    b"ptrace": ("anti-debug", Severity.MEDIUM, "anti-analysis"),
    b"IsDebuggerPresent": ("anti-debug", Severity.MEDIUM, "anti-analysis"),
    b"dlopen": ("dynamic-load", Severity.LOW, "loader"),
    b"LoadLibrary": ("dynamic-load", Severity.LOW, "loader"),
    b"GetProcAddress": ("dynamic-resolve", Severity.LOW, "loader"),
}

# A few well-known crypto constants (byte sequences) worth flagging with offset.
_CRYPTO_CONSTS: list[tuple[str, bytes]] = [
    ("AES S-box start", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])),
    ("SHA-256 init H0", (0x6A09E667).to_bytes(4, "little")),
    ("MD5 init A", (0x67452301).to_bytes(4, "little")),
]

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")


def _extract_strings(data: bytes, limit: int = 4000) -> list[bytes]:
    return _ASCII.findall(data)[:limit]


class TriageStage(Stage):
    name = "triage"
    tool = "builtin"
    required_tool = None

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        data = ctx.target.read_bytes()
        ent = shannon_entropy(data)
        ctx.target_info.entropy = ent

        if ent > 7.2:
            res.add(
                Finding(
                    title=f"High overall entropy ({ent:.2f} bits/byte)",
                    detail="Suggests packing, compression, or encryption. Expect a "
                    "small code surface plus a large high-entropy blob; consider "
                    "unpacking or a runtime dump before deep static reading.",
                    severity=Severity.MEDIUM,
                    tags=["packer"],
                    knowledge="confirmed-asm",
                )
            )

        strings = _extract_strings(data)
        blob = b"\n".join(strings)

        # Pattern hits (dedup, cap each category).
        seen: set[tuple[str, bytes]] = set()
        per_cat: dict[str, int] = {}
        for label, rx, sev, tag in _PATTERNS:
            for m in rx.findall(blob):
                key = (label, m)
                if key in seen:
                    continue
                seen.add(key)
                if per_cat.get(label, 0) >= 15:
                    continue
                per_cat[label] = per_cat.get(label, 0) + 1
                res.add(
                    Finding(
                        title=f"{label}: {m.decode('utf-8', 'replace')[:100]}",
                        severity=sev,
                        tags=[tag, "string"],
                        knowledge="read",
                    )
                )

        # Suspicious API names present as strings (imports confirm later).
        for api, (short, sev, tag) in _SUSPICIOUS_APIS.items():
            if api in data:
                off = data.find(api)
                res.add(
                    Finding(
                        title=f"References {api.decode()} ({short})",
                        detail="Name present in the file; confirm via import table / xrefs.",
                        severity=sev,
                        coordinate=f"0x{off:x}",
                        tags=[tag, "api"],
                        knowledge="read",
                    )
                )

        # Crypto constants with offsets (jump targets for the disassembler).
        for name, needle in _CRYPTO_CONSTS:
            off = data.find(needle)
            if off >= 0:
                res.add(
                    Finding(
                        title=f"Crypto constant: {name}",
                        detail="Characteristic constant table found; the routine using "
                        "it is a good disassembler jump target.",
                        severity=Severity.MEDIUM,
                        coordinate=f"0x{off:x}",
                        tags=["crypto"],
                        knowledge="confirmed-asm",
                    )
                )

        # Persist a strings dump artifact for later grepping.
        sdir = ctx.stage_dir(self.name)
        strings_path = sdir / "strings.txt"
        strings_path.write_text(
            "\n".join(s.decode("utf-8", "replace") for s in strings), encoding="utf-8"
        )
        res.artifacts.append(str(strings_path))
        res.summary = (
            f"entropy {ent:.2f}; {len(strings)} strings; "
            f"{len(res.findings)} triage findings"
        )
        if not res.findings:
            res.status = StageStatus.EMPTY
        return res
