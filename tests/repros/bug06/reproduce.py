#!/usr/bin/env python3
"""Deterministic clean-harness reproduction of BUG-06; no network traffic."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

TARGET = "serialization"
CASES = [
  [
    "rrsig-reparse-overflow",
    "c8871c8ba860b1edf195e960016badd99a69aba87b28adedf2190b343c349603",
    "12348580000100010000000005706c61696e042e00010000002e0001c00c002e00010000003c005e696e773594230d020000003c010001e8000000000000000000123485800003000100000000050000000000000000000000000000000000000000010000003c005e00010d021300003c77359400713fb30004d205706c61696e0474657374",
    [
      "System.OverflowException",
      "DnsRRSIGRecordData.ReadRecordData"
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
        {"finding": "BUG-06", "source": "PR #9 run 42404148894",
         "harness": "clean/uninstrumented", "status": status, "cases": rows},
        indent=2) + "\n", encoding="utf-8")
    for row in rows:
        print(row["case"] + ": " + ("expected" if row["expectation_met"] else "UNEXPECTED"))
    return 0 if status == "all_expected_observations" else 1

if __name__ == "__main__":
    sys.exit(main())
