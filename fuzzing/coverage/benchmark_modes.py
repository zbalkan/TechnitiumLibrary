#!/usr/bin/env python3
"""Measure clean-harness process startup versus repeated in-process parsing."""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


def compare(command: list[str], target: str, sample: Path,
            cold_runs: int = 8, repeated: int = 2000) -> dict:
    if not command or cold_runs < 1 or repeated < 1:
        raise ValueError("A command and positive iteration counts are required")
    flags = ["--replay", str(sample)] if target == "datagram" else [
        "--replay-target", target, str(sample)]
    durations = []
    for _ in range(cold_runs):
        start = time.perf_counter()
        result = subprocess.run([*command, *flags], capture_output=True,
                                timeout=10, check=False)
        if result.returncode:
            raise RuntimeError("Cold parser replay did not succeed")
        durations.append(time.perf_counter() - start)
    repeated_run = subprocess.run(
        [*command, "--benchmark", target, str(sample), str(repeated)],
        capture_output=True, timeout=60, check=True, text=True)
    in_process = json.loads(repeated_run.stdout)
    median_launch = statistics.median(durations)
    return {
        "target": target,
        "cold_process_runs": cold_runs,
        "median_cold_process_seconds": round(median_launch, 6),
        "in_process": in_process,
        "throughput_ratio_clean_only": round(
            in_process["operations_per_second"] * median_launch, 2),
        "interpretation": "Not an AFL++ persistent-mode benchmark. "
                          "Compares clean parser process overhead to in-process calls only.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="datagram")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cold-runs", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    report = compare(command, args.target, args.input, args.cold_runs, args.iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
