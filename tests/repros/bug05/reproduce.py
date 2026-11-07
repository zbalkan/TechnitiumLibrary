#!/usr/bin/env python3
"""Deterministic clean-harness reproduction of BUG-05; no network traffic."""
import argparse
import base64
import zlib
import hashlib
import json
import subprocess
import sys
from pathlib import Path

TARGET = "serialization"
CASES = [
  [
    "serializer-rejects-accepted-soa",
    "2067312653bc00f017eaad2acf6be31ba574f4141ee7cfcfe967f4dc8ff828d4",
    "",
    [
      "DnsClientException",
      "label cannot exceed 63 bytes"
    ]
  ],
  [
    "bounded-header-semantic-drift",
    "0ed15a57ab24fbb16e777b9eec6dd4396068017c3c70c01c9415f502de38ed4f",
    "1236010000010000000000010474652e2e000001000800002904d10c0000001e01000900000008400000010004746573",
    [
      "DNS message semantics changed during round-trip"
    ]
  ]
]
# Exact original input compressed for transport; digest checked at runtime.
CASES[0][2] = zlib.decompress(base64.b64decode("eNoTMmltYGAEQiBgLchJzMxjKUktLmFgYGNgPMADIhn+M9gwWDPnFRsiy3Nl5BeX5CYWl6QWAYXNsQMtCMWAAA4MDDh5DAxcMAYAQ8UYkQ==")).hex()
CONTROL = bytes.fromhex("12340100000100000000000001610000010001")

def invoke(dll, name, data, directory, expected=None):
    sample = directory / (name + ".bin")
    sample.write_bytes(data)
    cmd = ["dotnet", str(dll), "--replay-target", TARGET, str(sample)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        output = (result.stdout + "\n" + result.stderr)[:32768]
        observed = result.returncode != 0 and expected is not None and all(term in output for term in expected)
        if expected is None:
            observed = result.returncode == 0
        exit_code = result.returncode
    except subprocess.TimeoutExpired as exc:
        output = str(exc)
        observed = False
        exit_code = None
    (directory / (name + ".log")).write_text(output, encoding="utf-8")
    return {"case": name, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "exit_code": exit_code,
            "expected_markers": expected or [], "expectation_met": observed,
            "purpose": "known-bug-observation" if expected is not None else "healthy-control"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = [invoke(args.dll, "valid-control", CONTROL, args.output)]
    for name, digest, hexbytes, markers in CASES:
        payload = bytes.fromhex(hexbytes)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("Archived payload SHA-256 mismatch: " + name)
        rows.append(invoke(args.dll, name, payload, args.output, markers))
    status = "all_expected_observations" if all(r["expectation_met"] for r in rows) else "unexpected_result"
    (args.output / "report.json").write_text(json.dumps(
        {"finding": "BUG-05", "source": "PR #9 run 42404148894",
         "harness": "clean/uninstrumented", "status": status, "cases": rows},
        indent=2) + "\n", encoding="utf-8")
    for row in rows:
        print(row["case"] + ": " + ("expected" if row["expectation_met"] else "UNEXPECTED"))
    return 0 if status == "all_expected_observations" else 1

if __name__ == "__main__":
    sys.exit(main())
