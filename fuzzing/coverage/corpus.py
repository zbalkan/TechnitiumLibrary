#!/usr/bin/env python3
"""Promote reviewed DNS wire inputs to a content-addressed regression corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MAX_DNS_BYTES = 65535


def promote(source: Path, destination: Path) -> Path:
    payload = source.read_bytes()
    if not 0 < len(payload) <= MAX_DNS_BYTES:
        raise ValueError("DNS input must contain 1 through 65535 bytes")
    digest = hashlib.sha256(payload).hexdigest()
    target = destination / f"{digest}.bin"
    destination.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.read_bytes() != payload:
            raise ValueError("Existing corpus file does not match its SHA-256 name")
        return target
    target.write_bytes(payload)
    return target


def verify(directory: Path) -> int:
    """Check regression content addresses before using the saved corpus."""
    count = 0
    for path in sorted(directory.glob("*.bin")):
        payload = path.read_bytes()
        if not 0 < len(payload) <= MAX_DNS_BYTES:
            raise ValueError(f"{path}: invalid DNS input size")
        if path.stem != hashlib.sha256(payload).hexdigest():
            raise ValueError(f"{path}: filename does not match SHA-256")
        count += 1
    return count


def snapshot(seeds: Path, queue: Path, destination: Path) -> dict:
    """Archive byte-distinct fuzz inputs without claiming edge minimization."""
    destination.mkdir(parents=True, exist_ok=True)
    sources = [("seed", seeds)] + ([("queue", queue)] if queue.is_dir() else [])
    count = 0
    unique = set()
    entries = []
    for origin, folder in sources:
        pattern = "*" if origin == "seed" else "id:*"
        for sample in sorted(folder.glob(pattern)):
            if not sample.is_file():
                continue
            payload = sample.read_bytes()
            if len(payload) > MAX_DNS_BYTES:
                raise ValueError(f"{sample}: oversized fuzz input")
            count += 1
            digest = hashlib.sha256(payload).hexdigest()
            target = destination / f"{digest}.bin"
            if digest not in unique:
                if target.exists() and target.read_bytes() != payload:
                    raise ValueError("SHA-256 collision or mismatched existing snapshot")
                if not target.exists():
                    target.write_bytes(payload)
                unique.add(digest)
            entries.append({"source": origin, "name": sample.name, "sha256": digest})
    report = {
        "kind": "byte-deduplicated",
        "coverage_minimized": False,
        "input_count": count,
        "distinct_inputs": len(unique),
        "duplicates": count - len(unique),
        "entries": entries,
    }
    (destination / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    add = command.add_parser("promote")
    add.add_argument("--source", type=Path, required=True)
    add.add_argument("--destination", type=Path, required=True)
    check = command.add_parser("verify")
    check.add_argument("--directory", type=Path, required=True)
    saved = command.add_parser("snapshot")
    saved.add_argument("--seeds", type=Path, required=True)
    saved.add_argument("--queue", type=Path, required=True)
    saved.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "snapshot":
        info = snapshot(args.seeds, args.queue, args.destination)
        print(f"Snapshot: {info['distinct_inputs']} distinct of {info['input_count']} "
              "inputs (no edge minimization)")
    elif args.command == "promote":
        print(promote(args.source, args.destination))
    else:
        print(f"Verified {verify(args.directory)} reviewed regression inputs")


if __name__ == "__main__":
    main()
