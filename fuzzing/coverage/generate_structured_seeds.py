#!/usr/bin/env python3
"""Deterministic grammar-aware DNS mutations preserving selected wire scaffolding."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from generate_seeds import header, qname, question, rr

MAX_SEEDS = 256


def structured_seeds() -> dict[str, bytes]:
    """Vary one structural field at a time; do not assert all outputs are valid."""
    result: dict[str, bytes] = {}
    query = question("plain.test")
    pointer = b"\xc0\x0c"
    for flags in (0, 0x100, 0x200, 0x8000, 0x8180, 0x8580, 0x1000, 0xFFFF):
        result[f"flags-{flags:04x}"] = header(flags) + query

    for count in (0, 1, 2, 3, 255, 256, 65535):
        result[f"qdcount-{count}"] = header(qd=count) + query
        result[f"ancount-{count}"] = header(0x8180, an=count) + query

    # Compression pointer offsets and label length boundaries.
    for offset in (0, 1, 2, 11, 12, 13, 18, 255, 1023, 4095, 16383):
        compressed = struct.pack("!H", 0xC000 | offset)
        result[f"pointer-{offset}"] = header() + compressed + b"\x00\x01\x00\x01"
    for length in (0, 1, 62, 63, 64, 65, 127, 192, 255):
        result[f"label-{length}"] = header() + bytes([length]) + b"a" * min(length, 255) + b"\x00\x00\x01\x00\x01"

    rdata = {
        1: bytes([192, 0, 2, 10]),
        28: bytes.fromhex("20010db8000000000000000000000001"),
        15: struct.pack("!H", 10) + qname("mail.plain.test"),
        16: b"\x04fuzz",
        43: struct.pack("!HBB", 100, 13, 2) + bytes(range(32)),
        48: struct.pack("!HBB", 257, 3, 15) + bytes(range(32)),
        47: qname("next.plain.test") + b"\x00\x01\x40",
        50: b"\x01\x00\x00\x00\x00\x01\xaa\x00\x01\x40",
    }
    for kind, value in rdata.items():
        for declared in (0, 1, max(0, len(value) - 1), len(value), len(value) + 1, 65535):
            rr_header = pointer + struct.pack("!HHIH", kind, 1, 60, declared)
            result[f"rdata-{kind}-length-{declared}"] = (
                header(0x8180, an=1) + query + rr_header + value)

    for code in (8, 15, 65000):
        for declared in (0, 1, 2, 4, 5, 255, 65535):
            option = struct.pack("!HH", code, declared) + b"\xc0\x00\x02\x01"
            opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(option)) + option
            result[f"edns-{code}-length-{declared}"] = header(ar=1) + query + opt

    if len(result) > MAX_SEEDS:
        raise RuntimeError("Structured seed budget exceeded")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in structured_seeds().items():
        (args.output / name).write_bytes(data)
    print(f"structured corpus: {len(structured_seeds())} inputs")


if __name__ == "__main__":
    main()
