#!/usr/bin/env python3
"""Time-budgeted AFL++ edge-based minimization for the SharpFuzz .NET harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

EDGE = re.compile(r"[0-9]+:[0-9]+")
MAX_SIZE = 65535


def candidates(seeds: Path, queue: Path, max_queue: int) -> list[Path]:
    if max_queue < 0:
        raise ValueError("max_queue must be nonnegative")
    initial = sorted(path for path in seeds.iterdir() if path.is_file())
    discovered = sorted(queue.glob("id:*")) if queue.is_dir() else []
    discovered = [path for path in discovered if path.is_file()]
    if not max_queue:
        discovered = []
    elif len(discovered) > max_queue:
        discovered = [discovered[i * len(discovered) // max_queue]
                      for i in range(max_queue)]
    return initial + discovered


def read_coverage(path: Path) -> frozenset[int]:
    edges = set()
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not EDGE.fullmatch(line):
            raise ValueError("Invalid AFL++ coverage map")
        edges.add(int(line.split(":", 1)[0]))
    return frozenset(edges)


def measure_showmap(path: Path, target: list[str], seconds: float) -> frozenset[int] | None:
    packet = path.read_bytes()
    if not 0 < len(packet) <= MAX_SIZE or seconds <= 0:
        return None
    with tempfile.TemporaryDirectory(prefix="dns-showmap-") as temp:
        trace = Path(temp) / "trace"
        env = {**os.environ, "AFL_NO_FORKSRV": "1", "AFL_SKIP_BIN_CHECK": "1",
               "AFL_QUIET": "1"}
        command = ["afl-showmap", "-q", "-e", "-o", str(trace),
                   "-m", "none", "-t", "2000+", "--", *target]
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=env, start_new_session=True)
        try:
            proc.communicate(input=packet, timeout=seconds)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return None
        if proc.returncode or not trace.is_file():
            return None
        return read_coverage(trace)


def greedy_cover(samples: list[tuple[Path, frozenset[int]]]) -> list[Path]:
    missing = set().union(*(edges for _, edges in samples))
    remaining = samples[:]
    selected = []
    while missing:
        path, edges = max(remaining, key=lambda sample: len(sample[1] & missing))
        improvement = edges & missing
        if not improvement:
            raise RuntimeError("Unable to preserve measured coverage")
        selected.append(path)
        missing -= improvement
        remaining.remove((path, edges))
    return selected


def minimize(inputs: list[Path], destination: Path, measure, budget: float) -> dict:
    if budget <= 0:
        raise ValueError("budget must be positive")
    destination.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    measured = []
    ignored = []
    status = "complete"
    for path in inputs:
        remaining = budget - (time.monotonic() - start)
        if remaining <= 0:
            status = "partial"
            break
        edges = measure(path, min(remaining, 5))
        if edges:
            measured.append((path, edges))
        else:
            ignored.append(path.name)
    chosen = greedy_cover(measured)
    for path in chosen:
        destination.joinpath(hashlib.sha256(path.read_bytes()).hexdigest() + ".bin").write_bytes(
            path.read_bytes())
    elapsed = max(time.monotonic() - start, 0.001)
    report = {
        "status": status,
        "input_count": len(inputs),
        "measured_count": len(measured),
        "ignored_count": len(ignored),
        "remaining_count": len(inputs) - len(measured) - len(ignored),
        "selected_count": len(chosen),
        "measured_edges": len(set().union(*(edges for _, edges in measured))),
        "elapsed_seconds": round(elapsed, 2),
        "samples_per_second": round((len(measured) + len(ignored)) / elapsed, 2),
        "ignored_samples": ignored[:30],
    }
    (destination / "minimization.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", required=True, type=Path)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seconds", type=float, default=75)
    parser.add_argument("--max-queue", type=int, default=50)
    parser.add_argument("target", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    target = args.target[1:] if args.target and args.target[0] == "--" else args.target
    if not target:
        parser.error("target command required after --")
    inputs = candidates(args.seeds, args.queue, args.max_queue)
    report = minimize(inputs, args.output,
                      lambda path, budget: measure_showmap(path, target, budget),
                      args.seconds)
    print(json.dumps(report, indent=2))
    if report["measured_edges"] == 0:
        raise SystemExit("No instrumentation edges measured; inspect target and AFL++.")


if __name__ == "__main__":
    main()
