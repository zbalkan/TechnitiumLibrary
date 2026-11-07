#!/usr/bin/env python3
"""Generate deterministic DNS parser seed corpus, without external packages."""
from __future__ import annotations
import argparse
import struct
from pathlib import Path

DEFAULT_DOMAIN = "plain.test"
DEFAULT_POINTER = b"\xc0\x0c"
RR_HEADER_FORMAT = "!HHIH"

def qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"

def header(flags=0x0100, qd=1, an=0, ns=0, ar=0) -> bytes:
    return struct.pack("!HHHHHH", 0x1234, flags, qd, an, ns, ar)

def question(name=DEFAULT_DOMAIN, qtype=1) -> bytes:
    return qname(name) + struct.pack("!HH", qtype, 1)

def rr(name: bytes, rtype: int, payload: bytes, rrclass=1) -> bytes:
    return name + struct.pack(RR_HEADER_FORMAT, rtype, rrclass, 60, len(payload)) + payload

def seeds() -> dict[str, bytes]:
    query = question()
    pointer = DEFAULT_POINTER
    answer_a = rr(pointer, 1, b"\xc0\x00\x02\x01")
    answer_aaaa = rr(pointer, 28, bytes.fromhex("20010db8000000000000000000000001"))
    answer_cname = rr(pointer, 5, qname("alias." + DEFAULT_DOMAIN))
    answer_txt = rr(pointer, 16, b"\x04fuzz")
    answer_mx = rr(pointer, 15, struct.pack("!H", 10) + qname("mail." + DEFAULT_DOMAIN))
    soa = (qname("ns1." + DEFAULT_DOMAIN) + qname("hostmaster." + DEFAULT_DOMAIN) +
           struct.pack("!IIIII", 1, 3600, 600, 86400, 60))
    answer_soa = rr(pointer, 6, soa)
    opt = b"\x00" + struct.pack(RR_HEADER_FORMAT, 41, 1232, 0, 0)
    ede = struct.pack("!HHH", 15, 2, 15)
    opt_ede = b"\x00" + struct.pack(RR_HEADER_FORMAT, 41, 1232, 0, len(ede)) + ede
    return {
        "query-a": header() + query,
        "query-aaaa": header() + question("nsec.test", 28),
        "query-dnskey": header() + question("nsec3.test", 48),
        "query-txt": header() + question("blocked.fuzz.test", 16),
        "response-a": header(0x8580, an=1) + query + answer_a,
        "response-aaaa": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 28) + answer_aaaa,
        "response-cname": header(0x8580, an=1) + query + answer_cname,
        "response-txt": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 16) + answer_txt,
        "response-mx": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 15) + answer_mx,
        "response-soa": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 6) + answer_soa,
        "query-edns": header(ar=1) + query + opt,
        "response-ede": header(0x8183, ar=1) + query + opt_ede,
        "nxdomain": header(0x8183) + query,
        "short-header": b"\x12\x34\x01",
        "compression-loop": header() + pointer + struct.pack("!HH", 1, 1),
        "rr-truncated": header(0x8580, an=1) + query + answer_a[:-2],
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    corpus = seeds()
    for name, packet in corpus.items():
        (args.output / name).write_bytes(packet)
    print(f"seed corpus: {len(corpus)} files")

if __name__ == "__main__":
    main()
