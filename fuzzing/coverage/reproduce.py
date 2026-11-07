#!/usr/bin/env python3
"""Verify a fuzz finding against a separately built, uninstrumented harness.

A successful invocation confirms reproduction, not a security vulnerability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from triage import replay


def reproduce(bundle: Path, command: list[str]) -> bool:
    metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
    sample = bundle / "input.bin"
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    if digest != metadata["sha256"]:
        raise ValueError("Reproducer input does not match its recorded SHA-256")
    observed = replay(sample, command, metadata["timeout_seconds"],
                      metadata["target"] if metadata["target"] != "datagram" else None)
    matches = (observed["classification"] == metadata["classification"] and
               observed["signature"] == metadata["signature"] and
               observed["exit_code"] == metadata["exit_code"])
    print(json.dumps({"reproduced": matches, "expected_classification": metadata["classification"],
                      "observed_classification": observed["classification"],
                      "expected_exit_code": metadata["exit_code"],
                      "observed_exit_code": observed["exit_code"],
                      "expected_signature": metadata["signature"],
                      "observed_signature": observed["signature"]}, indent=2))
    return matches


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        parser.error("clean harness command required after --")
    try:
        ok = reproduce(args.bundle, command)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"Reproducer error: {exc}\n")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
