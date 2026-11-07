#!/usr/bin/env python3
"""Deterministic clean-harness reproduction of BUG-01; no network traffic."""
import argparse
import base64
import zlib
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
    "",
    [
      "System.IndexOutOfRangeException",
      "DeserializeDomainName"
    ]
  ]
]
# Exact original input compressed for transport; digest checked at runtime.
CASES[1][2] = zlib.decompress(base64.b64decode("eNpdkL0RgkAQhd+KJDDqUYChhsYY8CQypgVJtYCL/KnAGRuwBUu4xDoMJKAAZwzPE4QBv5kL9u7t231HMiO11mRKXngnuVI9NnmneCtFqwC8xCu5jsnBVGTM0NrRQPB4isN36GIpAlPr5rFr6+GskGRthbQzo7mdNUq3AtKgJzhVtFY42Hq9q/IrtDvDXfFrwFns8fs8aSwWnWxRk63b/B+ARuVIBCBve5ex9CLAbAPUH2CtkfADL71E0A==")).hex()
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
