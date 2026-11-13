#!/usr/bin/env python3
"""Exercise the live server-log oracle using one known malformed DNS packet.

The packet is a deterministic DNS compression loop. The pinned server logs its
DnsClientException and responds FORMERR. The production allowlist permits this
documented rejection; an intentionally empty allowlist must detect the record.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import fuzz_dns
import log_oracle

CONTROL_TYPE = "TechnitiumLibrary.Net.Dns.DnsClientException"
CONTROL_MESSAGE = "Error while reading domain name: max depth for decompression reached"
CONTROL_FRAME = re.compile(
    r"TechnitiumLibrary\.Net\.Dns\.DnsDatagram\.ReadFrom\(Stream s\)(?: in .+)?"
)


def control_packet() -> bytes:
    name, packet = fuzz_dns.corpus(20261106, 3)[2]
    if name != "compression-loop" or packet[12:14] != b"\xc0\x0c":
        raise ValueError("Compression-loop seed changed; update the negative control")
    return packet


def send(host: str, port: int, timeout: float) -> dict:
    payload = control_packet()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        response, remote = sock.recvfrom(65535)
    if len(response) < 12:
        raise ValueError("Negative-control response has a truncated DNS header")
    request_id, = struct.unpack_from("!H", payload)
    response_id, flags = struct.unpack_from("!HH", response)
    rcode = flags & 15
    if response_id != request_id or not flags & 0x8000 or rcode != 1:
        raise ValueError(
            f"Negative-control response invalid: id={response_id}, flags={flags:#x}, rcode={rcode}"
        )
    return {
        "status": "passed", "control": "compression-loop",
        "protocol": "udp", "packet_hex": payload.hex(),
        "response_hex": response.hex(), "response_rcode": rcode,
        "expected_logged_type": CONTROL_TYPE, "expected_logged_message": CONTROL_MESSAGE,
    }


def evaluate(log_dir: Path, baseline_dir: Path, allowlist: list[dict]) -> dict:
    strict = log_oracle.scan(log_dir, baseline_dir, [])
    ordinary = log_oracle.scan(log_dir, baseline_dir, allowlist)
    matches = [
        item for item in strict["exceptions"]
        if item["type"] == CONTROL_TYPE
        and item["message"] == CONTROL_MESSAGE
        and item["terminal_frame"] is not None
        and CONTROL_FRAME.fullmatch(item["terminal_frame"])
    ]
    detected = bool(matches) and strict["status"] == "failed"
    passed = detected and ordinary["status"] == "passed"
    return {
        "status": "passed" if passed else "failed",
        "control": "compression-loop", "logged_matches": len(matches),
        "strict_status": strict["status"],
        "strict_unexpected_exceptions": strict["unexpected_exceptions"],
        "production_status": ordinary["status"],
        "production_unexpected_exceptions": ordinary["unexpected_exceptions"],
        "matched_exceptions": matches,
        "reason": None if passed else "Missing logged rejection or incorrect oracle classification",
    }


def copy_and_verify(container: str, baseline: Path, rules: list[dict],
                    timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    attempts = 0
    last = None
    while True:
        attempts += 1
        with tempfile.TemporaryDirectory(prefix="dns-negative-control-") as root:
            logs = Path(root) / "logs"
            logs.mkdir()
            result = subprocess.run(
                ["docker", "cp", f"{container}:/etc/dns/logs/.", str(logs)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode:
                raise RuntimeError(f"docker cp failed ({result.returncode}): {result.stderr[:300]}")
            last = evaluate(logs, baseline, rules)
        last["attempts"] = attempts
        if last["status"] == "passed" or last["production_status"] == "failed":
            return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sending = sub.add_parser("send")
    sending.add_argument("--host", required=True)
    sending.add_argument("--port", type=int, default=53)
    sending.add_argument("--timeout", type=float, default=2)
    sending.add_argument("--output", type=Path, required=True)
    verifying = sub.add_parser("verify")
    verifying.add_argument("--container", default="tdns")
    verifying.add_argument("--baseline", type=Path, required=True)
    verifying.add_argument("--allowlist", type=Path, required=True)
    verifying.add_argument("--timeout", type=float, default=6)
    verifying.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "send":
            if args.timeout <= 0:
                raise ValueError("Timeout must be positive")
            report = send(args.host, args.port, args.timeout)
        else:
            if args.timeout <= 0:
                raise ValueError("Timeout must be positive")
            rules = log_oracle.validate_rules(json.loads(args.allowlist.read_text()))
            report = copy_and_verify(args.container, args.baseline, rules, args.timeout)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        report = {"status": "error", "control": "compression-loop",
                  "reason": f"{type(error).__name__}: {error}"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Network-path negative control ({args.command}): {report['status']}")
    if report["status"] != "passed":
        print(report.get("reason", ""), file=sys.stderr)
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
