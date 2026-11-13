#!/usr/bin/env python3
"""Verify an isolated DNS Server retains literal wire periods in QNAME responses."""
import argparse
import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, "/fixture")
from fuzz_dns import probe  # noqa: E402 - reuse the verified fixture health oracle

PAYLOAD = bytes.fromhex("12340100000100000000000003612e620000010001")
CONTROL = bytes.fromhex("123401000001000000000000016101620000010001")

def recv_n(sock, wanted):
    data = bytearray()
    while len(data) < wanted:
        part = sock.recv(wanted - len(data))
        if not part:
            return None
        data.extend(part)
    return bytes(data)

def exchange(host, port, proto, case_name, payload):
    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(payload, (host, port))
                reply, _ = sock.recvfrom(65535)
        else:
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(struct.pack("!H", len(payload)) + payload)
                header = recv_n(sock, 2)
                if header is None:
                    return {"case": case_name, "transport": proto, "outcome": "connection-closed"}
                length = struct.unpack("!H", header)[0]
                reply = recv_n(sock, length)
                if reply is None:
                    return {"case": case_name, "transport": proto, "outcome": "truncated-reply"}
        expected_question = payload[12:]
        # A response may omit the question or use compression. Record exact
        # octets; do not equate a mismatch with a vulnerability.
        echoed = len(reply) >= 12 + len(expected_question) and reply[12:12 + len(expected_question)] == expected_question
        return {"case": case_name, "transport": proto, "outcome": "response",
                "response_hex": reply.hex(), "question_wire_echoed": echoed,
                "rcode_low4": reply[3] & 15 if len(reply) >= 4 else None}
    except socket.timeout:
        return {"case": case_name, "transport": proto, "outcome": "timeout"}
    except OSError as exc:
        return {"case": case_name, "transport": proto, "outcome": type(exc).__name__, "error": str(exc)}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--port", default=53, type=int)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    before = probe(args.host, args.port)
    rows = [
        exchange(args.host, args.port, transport, name, payload)
        for name, payload in (("two-label-control", CONTROL), ("literal-period-label", PAYLOAD))
        for transport in ("udp", "tcp")
    ] if before is None else []
    after = probe(args.host, args.port) if before is None else None
    control_ok = all(
        row["outcome"] == "response" and row["question_wire_echoed"]
        for row in rows if row["case"] == "two-label-control"
    ) and len(rows) == 4
    preserved = all(
        row["outcome"] == "response" and row["question_wire_echoed"]
        for row in rows if row["case"] == "literal-period-label"
    ) and len(rows) == 4
    healthy = before is None and after is None
    report = {
        "finding": "BUG-02", "test_type": "isolated-server-corrected-behavior",
        "input_hex": PAYLOAD.hex(), "control_hex": CONTROL.hex(),
        "baseline_health": before or "healthy",
        "post_health": "not_run" if before is not None else (after or "healthy"),
        "control_preserved": control_ok, "literal_period_question_preserved": preserved,
        "results": rows,
        "status": "passed" if healthy and control_ok and preserved else "failed",
        "note": "Checks exact uncompressed question echo on UDP and TCP; not a comprehensive DNS compatibility test.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("isolated-server probe:", report["status"], [(x["case"], x["transport"], x["outcome"]) for x in rows])
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
