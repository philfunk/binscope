from binscope.util import shannon_entropy, sniff_filetype


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0          # single symbol -> 0
    high = shannon_entropy(bytes(range(256)) * 4)
    assert 7.9 <= high <= 8.0                               # uniform -> ~8


def test_sniff_elf(synthetic_sample):
    ft = sniff_filetype(synthetic_sample)
    assert ft.family == "native"
    assert ft.label == "ELF"
    assert ft.arch == "x86-64"
    assert ft.bits == 64
    assert ft.endianness == "little"


def test_sniff_unknown(tmp_path):
    p = tmp_path / "x.dat"
    p.write_bytes(b"not a known magic")
    ft = sniff_filetype(p)
    assert ft.family == "unknown"
