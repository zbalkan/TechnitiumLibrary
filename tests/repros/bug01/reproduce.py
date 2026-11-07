#!/usr/bin/env python3
"""Deterministic clean-harness reproduction of BUG-01; no network traffic."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

TARGET = "name"
CASES = [
  [
    "compressed-name-overflow",
    "313cbccd6e0d035dd604105c50e497a8956a91c513d9a4c1dfb4e7e28a7ffb4c",
    "3e3e3e503e3e7878783e3e403e3e923ec53e3e3e3f101026f0101010101010101010106162101010101010101010101010101010101010000010103010101010101010101010616210101010101010101010101010010101011010f40103e83e46383e3e021d01010effffc0010bffff0d020101010b0d02010101010101020107c00a00c010620000000000c0008000003e3eb07e3e783e0201010101e803000000c00a0a00",
    [
      "System.IndexOutOfRangeException",
      "DeserializeDomainName"
    ]
  ],
  [
    "name-overflow-variant",
    "c1633bda9ea3c4a95213d0ec7167473d841aa659f98196c2a251624908787de3",
    "3e3e3e503e3e7878783e3e403e3e923ec53e3e3e3f101010101010101010101010101061621010101010101010101010f710103eff10000000f40103e83e46383e3e021d01010e3e0bffff0d020100dfe3010101010505050578e439010100c000f40103e83e263810103e3e3e3e3e3e3e3e3e3e3e3e3e101010003d503e3e3e3e3e3e3e3e10004010101010101010101010103e3e3e3e3e3e3e3e253e3e3e3e3e10101010616200400a101010101010101010103e3e3e8181818181813e3e3e3e3e10101000007fff1010101010f79f1005050505050578050505046ce410101010101010008f01ff80101010f70f10101010101010102e10101010101061621010101110101010101010f79f10050505050505780505050578e439010100c000f40103e83e26383ec01062003d0100003e3eb07e010101e803110000c06b0a003e021d01010effffc0010b",
    [
      "System.IndexOutOfRangeException",
      "DeserializeDomainName"
    ]
  ]
]
CONTROL = bytes.fromhex("016100")

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
        {"finding": "BUG-01", "source": "PR #9 run 42404148894",
         "harness": "clean/uninstrumented", "status": status, "cases": rows},
        indent=2) + "\n", encoding="utf-8")
    for row in rows:
        print(row["case"] + ": " + ("expected" if row["expectation_met"] else "UNEXPECTED"))
    return 0 if status == "all_expected_observations" else 1

if __name__ == "__main__":
    sys.exit(main())
