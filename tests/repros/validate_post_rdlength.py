#!/usr/bin/env python3
"""Classify recorded fuzz reproducers against an updated parser build.

Exit nonzero only for invalid controls/infrastructure. A change in the known
failure signature is *not* automatically a fix; examine the archived logs.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ISSUES = ("bug01", "bug02", "bug04", "bug05", "bug06")



def inspect(dll: Path, file: Path) -> dict:
    response = subprocess.run(
        ["dotnet", str(dll), "--inspect", str(file)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if response.returncode:
        return {"status": "inspection_failed", "diagnostic": response.stderr[-1000:]}
    return json.loads(response.stdout)


def replace_first_wire_name_dot(data: bytes) -> bytes | None:
    """Preserve DNS name length bytes; replace only an octet 0x2e in a label."""
    result = bytearray(data)
    pos = 12
    while pos < len(result):
        length = result[pos]
        if length == 0 or length & 0xC0:
            break
        pos += 1
        if pos + length > len(result):
            break
        for index in range(pos, pos + length):
            if result[index] == 0x2e:
                result[index] = ord("-")
                return bytes(result)
        pos += length
    return None


def examine_serialization_cause(dll: Path, sample: Path) -> dict:
    original = inspect(dll, sample)
    changed = replace_first_wire_name_dot(sample.read_bytes())
    detail = {"initial_parse": original, "literal_dot_in_first_name": changed is not None}
    if changed is None:
        return detail
    alternative = sample.with_suffix(".dot-replaced.bin")
    alternative.write_bytes(changed)
    detail["dot_replaced_parse"] = inspect(dll, alternative)
    replay = subprocess.run(
        ["dotnet", str(dll), "--replay-target", "serialization", str(alternative)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    detail["dot_replaced_roundtrip_ok"] = replay.returncode == 0
    detail["dot_replaced_diagnostic"] = (replay.stdout + replay.stderr)[-900:]
    return detail


def run_one(name: str, dll: Path, out_root: Path) -> dict:
    out = out_root / name
    cmd = ["python3", f"tests/repros/{name}/reproduce.py", "--dll", str(dll),
           "--output", str(out)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
    report_file = out / "report.json"
    if not report_file.is_file():
        return {"finding": name, "status": "invalid", "reason": "missing report",
                "exit_code": result.returncode, "stderr": result.stderr[-2000:]}
    report = json.loads(report_file.read_text())
    cases = report.get("cases", [])
    if not cases:
        return {"finding": name, "status": "invalid", "reason": "missing cases"}
    controls = [case for case in cases
                if case.get("purpose") == "healthy-control"
                or "control" in case.get("name", "")]
    if not controls or not all(case["expectation_met"] for case in controls):
        status = "invalid"
    elif all(case["expectation_met"] for case in cases):
        status = "original_symptom_present"
    else:
        status = "changed_behavior_needs_triage"
    relevant = []
    for case in cases:
        if case in controls:
            continue
        key = case.get("case", case.get("name", "unknown"))
        log = out / (key + ".log")
        detail = {"case": key, "recorded_marker_matched": case["expectation_met"],
                  "diagnostic_excerpt": log.read_text(errors="replace")[-1500:]
                  if log.exists() else None}
        if name in ("bug04", "bug05", "bug06"):
            detail["cause_exploration"] = examine_serialization_cause(dll, out / (key + ".bin"))
        relevant.append(detail)
    return {"finding": name, "status": status, "exit_code": result.returncode,
            "controls_ok": all(case["expectation_met"] for case in controls),
            "cases": relevant}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--parser-dll", type=Path, required=True)
    p.add_argument("--name-dll", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for name in ISSUES:
        dll = args.name_dll if name == "bug02" else args.parser_dll
        try:
            result = run_one(name, dll, args.output)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            result = {"finding": name, "status": "invalid", "reason": str(exc)}
        results.append(result)
        print(json.dumps(result, sort_keys=True), flush=True)
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    return int(any(result["status"] == "invalid" for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
