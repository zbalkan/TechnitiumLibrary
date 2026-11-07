#!/usr/bin/env python3
"""Compare Technitium DNS wire parsing with dnspython, without assuming equivalence."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import dns.exception
import dns.message


def independent(packet: bytes) -> dict:
    try:
        parsed = dns.message.from_wire(packet, ignore_trailing=False)
    except (dns.exception.DNSException, ValueError, OverflowError) as exc:
        return {"accepted": False, "reason": type(exc).__name__}
    return {
        "accepted": True,
        "id": parsed.id,
        "qr": bool(parsed.flags & 0x8000),
        "opcode": (parsed.flags >> 11) & 0x0F,
        # Low four RCODE bits are comparable even when EDNS extends the code.
        "rcode_low4": parsed.rcode() & 0x0F,
    }


def library(path: Path, command: list[str], timeout: float = 5) -> dict:
    try:
        done = subprocess.run([*command, "--inspect", str(path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"tool_error": type(exc).__name__}
    if done.returncode != 0:
        return {"tool_error": "nonzero-exit", "exit_code": done.returncode,
                "stderr": done.stderr.decode(errors="replace")[:2000]}
    try:
        result = json.loads(done.stdout)
    except (json.JSONDecodeError, UnicodeError):
        return {"tool_error": "invalid-json"}
    if not isinstance(result, dict) or not isinstance(result.get("accepted"), bool):
        return {"tool_error": "invalid-schema"}
    return result


def discrepancy(left: dict, right: dict) -> list[str]:
    if "tool_error" in left:
        return ["library_tool_error"]
    if left["accepted"] != right["accepted"]:
        return ["acceptance"]
    if not left["accepted"]:
        return []
    different = []
    for field in ("id", "qr", "opcode"):
        if left.get(field) != right.get(field):
            different.append(field)
    if (int(left.get("rcode", -1)) & 0x0F) != right.get("rcode_low4"):
        different.append("rcode_low4")
    return different


def analyze(paths: list[Path], command: list[str], timeout: float = 5) -> dict:
    cases = []
    counts = {"both_accepted": 0, "both_rejected": 0,
              "acceptance_disagreement": 0, "semantic_disagreement": 0,
              "library_tool_error": 0}
    for path in paths:
        payload = path.read_bytes()
        left = library(path, command, timeout)
        right = independent(payload)
        difference = discrepancy(left, right)
        if difference:
            if "library_tool_error" in difference:
                counts["library_tool_error"] += 1
            elif "acceptance" in difference:
                counts["acceptance_disagreement"] += 1
            else:
                counts["semantic_disagreement"] += 1
            cases.append({"input_sha256": hashlib.sha256(payload).hexdigest(),
                          "name": path.name, "differences": difference,
                          "library": left, "independent": right})
        elif left["accepted"]:
            counts["both_accepted"] += 1
        else:
            counts["both_rejected"] += 1
    return {"engine": "dnspython", "total_inputs": len(paths), "counts": counts,
            "discrepancies": cases,
            "interpretation": "Differential results are review leads, not confirmed bugs."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-cases", type=int, default=150)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command or args.max_cases < 1:
        parser.error("Nonempty command and positive maximum required")
    available = sorted(path for path in args.seeds.iterdir() if path.is_file())
    if len(available) > args.max_cases:
        available = [available[i * len(available) // args.max_cases]
                     for i in range(args.max_cases)]
    report = analyze(available, command, args.timeout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Differential DNS inputs:", report["total_inputs"])
    print("Differential outcome counts:", report["counts"])


if __name__ == "__main__":
    main()
