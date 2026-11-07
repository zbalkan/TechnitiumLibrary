#!/usr/bin/env python3
"""Deterministic clean-harness reproduction of BUG-04; no network traffic."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

TARGET = "serialization"
CASES = [
  [
    "invalid-label-after-serialization",
    "3dd9361f01319f915d5e1fd5f5112bc52c6be2d8af15b71314ab80341f6a0510",
    "12340100000100000000000105576c61692e0475657374000001000100002c04010008000f0004c0000201",
    [
      "Serialized valid datagram cannot be parsed",
      "label length cannot exceed 63 bytes"
    ]
  ],
  [
    "truncated-after-serialization",
    "50b8b8591bf9550427f53989bd41a5fd68af2bfab79f9a0d78fd1ab99e686a76",
    "123481400000000000010000052e6c61696e04746573740017010001c00c002a000152348180000100028080",
    [
      "Serialized valid datagram cannot be parsed",
      "System.IO.EndOfStreamException"
    ]
  ]
]
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
        {"finding": "BUG-04", "source": "PR #9 run 42404148894",
         "harness": "clean/uninstrumented", "status": status, "cases": rows},
        indent=2) + "\n", encoding="utf-8")
    for row in rows:
        print(row["case"] + ": " + ("expected" if row["expectation_met"] else "UNEXPECTED"))
    return 0 if status == "all_expected_observations" else 1

if __name__ == "__main__":
    sys.exit(main())
