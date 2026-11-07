#!/usr/bin/env python3
"""Parse AFL++ campaign statistics and emit comparable JSON and Markdown summaries."""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path


def stats(path: Path) -> dict[str, str]:
    result = {}
    if not path.is_file():
        return result
    for line in path.read_text(errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def plot(path: Path) -> dict:
    """Find recorded coverage growth without assuming specific AFL++ column order."""
    if not path.is_file():
        return {"samples": 0}
    rows = []
    with path.open(newline="", errors="replace") as file:
        reader = csv.DictReader((line for line in file if line.strip()))
        if reader.fieldnames is None:
            return {"samples": 0}
        reader.fieldnames = [field.strip().lstrip("# ").strip() for field in reader.fieldnames]
        for row in reader:
            if row:
                rows.append({key.strip(): (value or "").strip() for key, value in row.items()
                             if key})
    if not rows:
        return {"samples": 0}
    # AFL++ versions use either total_edges or edges_found in plot_data.
    field = next((name for name in ("total_edges", "edges_found")
                  if name in rows[0]), None)
    result = {"samples": len(rows)}
    if field:
        try:
            values = [int(float(row[field])) for row in rows if row.get(field)]
        except ValueError:
            values = []
        if values:
            result.update(first_edges=values[0], last_edges=values[-1],
                          edge_growth=values[-1] - values[0])
    return result


def summarize(findings: Path, target: str, planned_minutes: int) -> dict:
    root = findings / "default"
    report = stats(root / "fuzzer_stats")
    def numeric(key: str):
        try:
            return float(report[key].rstrip("%"))
        except (KeyError, ValueError):
            return None

    values = {
        "target": target,
        "commit": os.getenv("GITHUB_SHA", "unknown"),
        "planned_minutes": planned_minutes,
        "executions": numeric("execs_done"),
        "execs_per_sec": numeric("execs_per_sec"),
        "corpus_count": numeric("corpus_count"),
        "saved_crashes": numeric("saved_crashes"),
        "saved_hangs": numeric("saved_hangs"),
        "stability_percent": numeric("stability"),
        "bitmap_coverage_percent": numeric("bitmap_cvg"),
        "last_find_seconds": numeric("time_wo_finds"),
        "coverage_series": plot(root / "plot_data"),
        "instrumentation_note": "AFL++ bitmap/edge metrics are not source or branch coverage.",
    }
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--minutes", required=True, type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = summarize(args.findings, args.target, args.minutes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as output:
            output.write(f"\n### AFL++ {args.target} campaign\n\n")
            output.write("| Measure | Value |\n|---|---:|\n")
            for label, field in (("Duration (minutes)", "planned_minutes"),
                                 ("Executions", "executions"),
                                 ("Execs/sec", "execs_per_sec"),
                                 ("Queue entries", "corpus_count"),
                                 ("Saved crashes", "saved_crashes"),
                                 ("Saved hangs", "saved_hangs"),
                                 ("Bitmap coverage (%)", "bitmap_coverage_percent"),
                                 ("Stability (%)", "stability_percent")):
                output.write(f"| {label} | {summary[field]} |\n")
            output.write("\nBitmap coverage does not measure source-code coverage.\n")


if __name__ == "__main__":
    main()
