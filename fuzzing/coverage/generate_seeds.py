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
    # RFC 6891 EDNS option cases: valid shape and malformed lengths both
    # belong in the mutation corpus. They are not automatically classified
    # as valid by the semantic oracle.
    ecs = struct.pack("!HBB", 1, 24, 0) + bytes([192, 0, 2])
    opt_ecs = b"\x00" + struct.pack(RR_HEADER_FORMAT, 41, 1232, 0, 4 + len(ecs))
    opt_ecs += struct.pack("!HH", 8, len(ecs)) + ecs
    opt_unknown = b"\x00" + struct.pack(RR_HEADER_FORMAT, 41, 1232, 0, 6)
    opt_unknown += struct.pack("!HH", 65000, 2) + b"\xab\xcd"

    # Keep security-sensitive branches reachable with structured but not
    # necessarily cryptographically valid DNSSEC key and proof material.
    ds = struct.pack("!HBB", 1234, 13, 2) + bytes(range(32))
    dnskey = struct.pack("!HBB", 257, 3, 15) + bytes(range(32))
    nsec = qname("next.plain.test") + b"\x00\x01\x40"
    nsec3 = bytes([1, 0]) + struct.pack("!H", 0) + b"\x00\x01\x01"
    nsec3 += b"\xaa" + b"\x00\x01\x40"
    rrsig = struct.pack("!HBBIIIH", 1, 13, 2, 60, 2000000000, 1900000000, 1234)
    rrsig += qname(DEFAULT_DOMAIN) + b"\x00" * 64

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
        "query-ds": header() + question("nsec.test", 43),
        "query-rrsig": header() + question("nsec.test", 46),
        "query-nsec": header() + question("nsec.test", 47),
        "query-nsec3": header() + question("nsec3.test", 50),
        "response-ns": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 2) +
                       rr(pointer, 2, qname("ns1." + DEFAULT_DOMAIN)),
        "response-ptr": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 12) +
                        rr(pointer, 12, qname("ptr." + DEFAULT_DOMAIN)),
        "response-ds": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 43) +
                       rr(pointer, 43, ds),
        "response-dnskey-ed25519": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 48) +
                                   rr(pointer, 48, dnskey),
        "response-nsec": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 47) +
                         rr(pointer, 47, nsec),
        "response-nsec3": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 50) +
                          rr(pointer, 50, nsec3),
        "response-rrsig": header(0x8580, an=1) + question(DEFAULT_DOMAIN, 46) +
                          rr(pointer, 46, rrsig),
        "query-edns-ecs": header(ar=1) + query + opt_ecs,
        "query-edns-unknown": header(ar=1) + query + opt_unknown,
        "query-two-questions": header(qd=2) + query + question("nsec.test", 28),
        "response-mixed-sections": header(0x8580, an=1, ns=1, ar=1) + query +
                                   answer_a + rr(pointer, 2, qname("ns1." + DEFAULT_DOMAIN)) + opt,
        "malformed-question-count": header(qd=2) + query,
        "malformed-rdata-short": header(0x8580, an=1) + query +
                                 pointer + struct.pack(RR_HEADER_FORMAT, 1, 1, 60, 4) + b"\x01",
        "malformed-label-64": header() + bytes([64]) + b"a" * 64 +
                              b"\x00" + struct.pack("!HH", 1, 1),
        "malformed-edns-option-length": header(ar=1) + query +
                                       b"\x00" + struct.pack(RR_HEADER_FORMAT, 41, 1232, 0, 4) +
                                       struct.pack("!HH", 8, 8),
        "malformed-edns-truncated": (header(ar=1) + query + opt_ede)[:-1],
        "malformed-compression-forward": header() + b"\xc0\x14" +
                                         struct.pack("!HH", 1, 1),
        "malformed-opt-duplicate": header(ar=2) + query + opt + opt,
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
