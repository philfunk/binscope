"""Small shared helpers: subprocess running, hashing, filetype sniffing."""
from __future__ import annotations

import hashlib
import math
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence


@dataclass
class RunResult:
    """Outcome of a subprocess invocation."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def which(name: str) -> Optional[str]:
    """Locate an executable on PATH, returning its absolute path or None."""
    return shutil.which(name)


def run(
    argv: Sequence[str],
    *,
    timeout: Optional[float] = None,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    input_text: Optional[str] = None,
) -> RunResult:
    """Run a command, capturing stdout/stderr as text. Never raises on non-zero.

    The target binary is always passed as an argument; we never `cd` into its
    directory nor invoke it as the command here.
    """
    argv = [str(a) for a in argv]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
            input=input_text,
        )
        return RunResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - start,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            argv=argv,
            returncode=-1,
            stdout=(exc.stdout or b"").decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
            duration=time.monotonic() - start,
            timed_out=True,
        )
    except FileNotFoundError:
        return RunResult(
            argv=argv,
            returncode=127,
            stdout="",
            stderr=f"executable not found: {argv[0]}",
            duration=time.monotonic() - start,
        )


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). High (>7.2) suggests packed/encrypted."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# Magic-byte signatures -> (label, coarse family). First match wins.
_MAGICS: list[tuple[bytes, str, str]] = [
    (b"\x7fELF", "ELF", "native"),
    (b"MZ", "PE/COFF (DOS MZ)", "native"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32 (BE)", "native"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64 (BE)", "native"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32 (LE)", "native"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 (LE)", "native"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat / Java class", "native"),
    (b"dex\n", "Android DEX", "android"),
    (b"PK\x03\x04", "ZIP container (apk/jar/ipa/asar?)", "container"),
    (b"\x00asm", "WebAssembly", "wasm"),
    (b"!<arch>", "ar archive / .deb", "container"),
    (b"\x1f\x8b", "gzip", "container"),
    (b"\xfd7zXZ\x00", "xz", "container"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip", "container"),
]


@dataclass
class FileType:
    label: str
    family: str  # native / android / container / wasm / unknown
    arch: str = "unknown"
    bits: int = 0
    endianness: str = "unknown"


def sniff_filetype(path: Path) -> FileType:
    """Identify a file from its magic bytes and a shallow header parse."""
    with path.open("rb") as fh:
        head = fh.read(64)
    label, family = "unknown", "unknown"
    for sig, lab, fam in _MAGICS:
        if head.startswith(sig):
            label, family = lab, fam
            break
    ft = FileType(label=label, family=family)
    if head.startswith(b"\x7fELF") and len(head) >= 20:
        ft.bits = 32 if head[4] == 1 else 64
        ft.endianness = "little" if head[5] == 1 else "big"
        machine = int.from_bytes(head[18:20], ft.endianness)
        ft.arch = {
            0x03: "x86",
            0x3E: "x86-64",
            0x28: "arm",
            0xB7: "aarch64",
            0xF3: "riscv",
            0x08: "mips",
        }.get(machine, f"elf-machine-0x{machine:x}")
    elif head.startswith(b"MZ"):
        ft.label = "PE/COFF"  # refined by rizin/ghidra later
    return ft


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)
