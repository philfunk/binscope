"""Shared fixtures. Tests run without any external RE tool installed."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest


@pytest.fixture
def synthetic_sample(tmp_path: Path) -> Path:
    """A tiny ELF-ish file carrying recognizable markers for the triage stage.

    Not a real executable — just enough magic bytes, strings, and a crypto
    constant for the stdlib-only triage parser to find things.
    """
    hdr = b"\x7fELF\x02\x01" + b"\x00" * 12       # 64-bit LE ELF header stub
    hdr += struct.pack("<H", 0x3E)                 # e_machine = x86-64 at offset 18
    body = hdr + b"\x00" * 200
    body += b"https://evil.example.com/beacon\x00"
    body += b"VirtualAlloc\x00WriteProcessMemory\x00LoadLibraryA\x00IsDebuggerPresent\x00"
    body += b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    body += bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])  # AES S-box start
    body += b"cmd.exe /c whoami\x00"
    body += b"A" * 64
    p = tmp_path / "sample.bin"
    p.write_bytes(body)
    return p
