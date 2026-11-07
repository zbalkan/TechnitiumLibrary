#!/usr/bin/env python3
"""Probe an isolated Technitium DNS Server with a valid wire label containing '.'.

This tests whether the application echoes/transforms the question; it does not
assume network exploitation, or require an error response to malformed input.
"""
import argparse
import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, "/fixture")
from fuzz_dns import probe  # noqa: E402 - reuse the verified fixture health oracle

PAYLOAD = bytes.fromhex("12340100000100000000000003612e620000010001")

def recv_n(sock, wanted):
    data = bytearray()
    while len(data) < wanted:
        part = sock.recv(wanted - len(data))
        if not part:
            return None
        data.extend(part)
    return bytes(data)

def exchange(host, port, proto):
    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(PAYLOAD, (host, port))
                reply, _ = sock.recvfrom(65535)
        else:
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(struct.pack("!H", len(PAYLOAD)) + PAYLOAD)
                header = recv_n(sock, 2)
                if header is None:
                    return {"transport": proto, "outcome": "connection-closed"}
                length = struct.unpack("!H", header)[0]
                reply = recv_n(sock, length)
                if reply is None:
                    return {"transport": proto, "outcome": "truncated-reply"}
        expected_question = PAYLOAD[12:]
        # A response may omit the question or use compression. Record exact
        # octets; do not equate a mismatch with a vulnerability.
        echoed = len(reply) >= 12 + len(expected_question) and reply[12:12 + len(expected_question)] == expected_question
        return {"transport": proto, "outcome": "response",
                "response_hex": reply.hex(), "question_wire_echoed": echoed,
                "rcode_low4": reply[3] & 15 if len(reply) >= 4 else None}
    except socket.timeout:
        return {"transport": proto, "outcome": "timeout"}
    except OSError as exc:
        return {"transport": proto, "outcome": type(exc).__name__, "error": str(exc)}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--port", default=53, type=int)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    before = probe(args.host, args.port)
    rows = [exchange(args.host, args.port, t) for t in ("udp", "tcp")] if before is None else []
    after = probe(args.host, args.port) if before is None else None
    report = {
        "finding": "BUG-02", "test_type": "isolated-server-reachability",
        "input_hex": PAYLOAD.hex(), "baseline_health": before or "healthy",
        "post_health": after or "healthy", "results": rows,
        "status": "passed" if before is None and after is None else "failed",
        "note": "A healthy daemon and response observables are not proof of semantic safety.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("isolated-server probe:", report["status"], [(x["transport"], x["outcome"]) for x in rows])
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
