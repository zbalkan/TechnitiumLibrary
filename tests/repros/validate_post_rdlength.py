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
        relevant.append({"case": key, "recorded_marker_matched": case["expectation_met"],
                         "diagnostic_excerpt": log.read_text(errors="replace")[-1500:]
                         if log.exists() else None})
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
