#!/usr/bin/env python3
"""Generate label-boundary counterexample and compare real library decode/encode."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

CASES = (
    ("normal-two-labels-control", "0161016200", "0161016200"),
    ("literal-dot-in-one-label", "03612e6200", "0161016200"),
    ("single-label-control", "016100", "016100"),
)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for name, wire_hex, expected_encoded_hex in CASES:
        data = bytes.fromhex(wire_hex)
        sample = args.output / (name + ".bin")
        sample.write_bytes(data)
        try:
            process = subprocess.run(["dotnet", str(args.dll), str(sample)],
                                     capture_output=True, text=True, timeout=15, check=False)
            (args.output / (name + ".log")).write_text(
                (process.stdout + "\n" + process.stderr)[:32768], encoding="utf-8")
            detail = json.loads(process.stdout) if process.returncode == 0 else {}
            observed = detail.get("encoded_hex")
            match = (process.returncode == 0 and observed == expected_encoded_hex)
        except (subprocess.TimeoutExpired, ValueError) as exc:
            observed, match = str(exc), False
        results.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                        "original_wire_hex": wire_hex, "expected_encoded_hex": expected_encoded_hex,
                        "observed_encoded_hex": observed, "expectation_met": match,
                        "known_defect": name == "literal-dot-in-one-label"})
        print(f"{name}: {'expected' if match else 'UNEXPECTED'}")
    passed = all(row["expectation_met"] for row in results)
    (args.output / "report.json").write_text(json.dumps({
        "finding": "BUG-02", "observed_source_level_defect": passed,
        "status": "expected_behavior_observed" if passed else "unexpected_result",
        "cases": results}, indent=2) + "\n", encoding="utf-8")
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
