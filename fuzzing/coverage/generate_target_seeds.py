#!/usr/bin/env python3
"""Structured AFL++ seed inputs for focused DNS parser targets."""
from __future__ import annotations
import argparse
import struct
from pathlib import Path

from generate_seeds import qname, seeds as datagram_seeds
from generate_structured_seeds import structured_seeds

TARGETS = ("name", "rdata", "edns", "dnssec", "serialization")


def target_seeds(target: str) -> dict[str, bytes]:
    if target == "serialization":
        return {**datagram_seeds(), **structured_seeds()}
    if target == "name":
        return {
            "root": b"\x00",
            "one-label": qname("a"),
            "multiple-labels": qname("host.plain.test"),
            "max-label": bytes([63]) + b"a" * 63 + b"\x00",
            "pointer-loop": b"\xc0\x00",
            "pointer-outside": b"\xc0\xff",
            "pointer-short": b"\xc0",
            "truncated-label": b"\x08abc",
            "invalid-label": b"\x40" + b"x" * 64 + b"\x00",
            "compression-chain": b"\x01a\xc0\x00",
            "empty": b"",
        }
    if target == "rdata":
        # Prefix selects the fixed target record type, NOT the wire RDATA.
        return {
            "a": b"\x00\xc0\x00\x02\x01",
            "ns": b"\x01" + qname("ns1.plain.test"),
            "cname": b"\x02" + qname("alias.plain.test"),
            "soa": b"\x03" + qname("ns.plain.test") +
                   qname("host.plain.test") + struct.pack("!IIIII", 1, 3600, 600, 86400, 60),
            "ptr": b"\x04" + qname("ptr.plain.test"),
            "mx": b"\x05" + struct.pack("!H", 10) + qname("mail.plain.test"),
            "txt": b"\x06\x04fuzz",
            "aaaa": b"\x07" + bytes.fromhex("20010db8000000000000000000000001"),
            "srv": b"\x08" + struct.pack("!HHH", 10, 5, 53) + qname("ns.plain.test"),
            "naptr": b"\x09" + b"\x00\x01\x00\x01\x01s\x03sip\x00" + qname("plain.test"),
            "rdata-short": b"\x00\x01",
            "rdata-empty": b"\x00",
        }
    if target == "edns":
        ecs = struct.pack("!HBB", 1, 24, 0) + bytes([192, 0, 2])
        return {
            "empty": b"",
            "ecs": struct.pack("!HH", 8, len(ecs)) + ecs,
            "ede": struct.pack("!HHH", 15, 2, 15),
            "unknown": struct.pack("!HH", 65000, 2) + b"\xab\xcd",
            "invalid-opt-length": struct.pack("!HH", 8, 8),
            "truncated-ecode": b"\x00\x0f\x00",
            "combined": struct.pack("!HH", 8, len(ecs)) + ecs + struct.pack("!HHH", 15, 2, 15),
        }
    if target == "dnssec":
        # Prefix selects DS, RRSIG, NSEC, DNSKEY, NSEC3, or NSEC3PARAM.
        return {
            "ds": b"\x00" + struct.pack("!HBB", 1234, 13, 2) + bytes(range(32)),
            "rrsig": b"\x01" + struct.pack("!HBBIIIH", 1, 13, 2, 60,
                                         2000000000, 1900000000, 1234) +
                     qname("plain.test") + bytes(64),
            "nsec": b"\x02" + qname("next.plain.test") + b"\x00\x01\x40",
            "dnskey": b"\x03" + struct.pack("!HBB", 257, 3, 15) + bytes(range(32)),
            "nsec3": b"\x04" + b"\x01\x00\x00\x00\x00\x01\xaa\x00\x01\x40",
            "nsec3param": b"\x05" + b"\x01\x00\x00\x00\x00",
            "short-dnskey": b"\x03\x01",
            "short-rrsig": b"\x01",
        }
    raise ValueError(f"Unknown target: {target}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    entries = target_seeds(args.target)
    for name, packet in entries.items():
        (args.output / name).write_bytes(packet)
    print(f"{args.target}: {len(entries)} focused seeds")


if __name__ == "__main__":
    main()
