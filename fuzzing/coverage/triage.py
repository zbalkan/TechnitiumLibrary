#!/usr/bin/env python3
"""Reproduce AFL++ findings using an uninstrumented DNS parser harness.

The tool records candidate evidence, not confirmed vulnerabilities. A
stored DnsDatagram.ParsingException is normal rejection and replay exits 0.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

MAX_DNS_BYTES = 65535
MAX_LOG_BYTES = 32768
MAX_CANDIDATES = 100
SIGNATURE_LINE = re.compile(r"^\s*(?:Unhandled exception\.|[A-Za-z][A-Za-z0-9_.+]*(?:Exception|Error):|at )")
VOLATILE = re.compile(r"0x[0-9a-fA-F]+|:\s*line\s+\d+")
CLASSIFICATIONS = ("non_reproducible", "reproduced_exception", "reproduced_timeout",
                   "abnormal_exit", "runner_error", "oversized_input")


def candidates(findings: Path, max_candidates: int = MAX_CANDIDATES) -> list[tuple[str, Path]]:
    if max_candidates < 1:
        raise ValueError("max_candidates must be positive")
    found = []
    for group, folder in (("crash", "crashes"), ("hang", "hangs")):
        root = findings / "default" / folder
        if root.is_dir():
            found.extend((group, path) for path in sorted(root.glob("id:*"))
                         if path.is_file())
    if len(found) > max_candidates:
        raise ValueError(f"Found {len(found)} candidates; explicit triage limit is {max_candidates}")
    return found


def signature(text: str, outcome: str) -> str:
    relevant = [VOLATILE.sub("<variable>", line.strip())
                for line in text.splitlines() if SIGNATURE_LINE.match(line)]
    # Grouping by exception and first stack frames is provisional;
    # one cluster does not necessarily imply a single root cause.
    return outcome + "|" + "|".join(relevant[:5])


def replay(path: Path, command: list[str], timeout: float, target: str | None = None) -> dict:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    result = {"sha256": digest, "bytes": len(payload), "classification": "",
              "exit_code": None, "signature": "", "output": ""}
    if len(payload) > MAX_DNS_BYTES:
        result["classification"] = "oversized_input"
        return result
    try:
        replay_args = (["--replay-target", target, str(path)] if target else
                       ["--replay", str(path)])
        completed = subprocess.run([*command, *replay_args],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
        result["exit_code"] = completed.returncode
        output = completed.stdout[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
        if completed.returncode == 0:
            outcome = "non_reproducible"
        elif "Unhandled exception" in output:
            # The .NET runtime may abort with SIGABRT (-6) after printing
            # an unhandled managed exception; retain the precise exit code.
            outcome = "reproduced_exception"
        else:
            outcome = "abnormal_exit"
    except subprocess.TimeoutExpired as exc:
        outcome = "reproduced_timeout"
        output = (exc.stdout or b"")[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
    except OSError as exc:
        outcome = "runner_error"
        output = f"{type(exc).__name__}: {exc}"
    result["classification"] = outcome
    result["signature"] = hashlib.sha256(signature(output, outcome).encode()).hexdigest()
    result["output"] = output
    return result



def write_reproducers(cases: list[dict], destination: Path, target: str,
                      timeout: float, source_commit: str) -> list[dict]:
    """Produce one standalone, byte-exact reproducer for each failure signature."""
    groups: dict[str, list[dict]] = {}
    for case in cases:
        if case["classification"] in ("non_reproducible", "runner_error", "oversized_input"):
            continue
        groups.setdefault(case["signature"], []).append(case)

    result = []
    for sig, members in sorted(groups.items()):
        # Prefer a small, stable reproducer. No attempt to alter or minimize
        # bytes is made: even a one-byte change requires fresh validation.
        case = min(members, key=lambda item: (item["bytes"], item["sha256"]))
        folder = destination / "reproducers" / sig
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(destination / case["evidence"], folder / "input.bin")
        metadata = {
            "schema_version": 1,
            "source_commit": source_commit,
            "target": target,
            "sha256": case["sha256"],
            "bytes": case["bytes"],
            "classification": case["classification"],
            "exit_code": case["exit_code"],
            "signature": sig,
            "timeout_seconds": timeout,
            "candidate_count": len(members),
            "candidate_hashes": sorted({item["sha256"] for item in members}),
            "evidence_kind": "unmodified AFL++ candidate; not minimized",
        }
        (folder / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        (folder / "replay-output.txt").write_text(case["output"], encoding="utf-8")
        command = ("dotnet DnsParserFuzz.dll --replay-target " + target + " input.bin"
                   if target != "datagram" else "dotnet DnsParserFuzz.dll --replay input.bin")
        readme = (
            "# DNS parser fuzzing reproducer\n\n"
            "This folder contains an **unmodified AFL++ input** that reproduced "
            "a process-level finding against the **clean, uninstrumented** harness. "
            "It is not a confirmed vulnerability or a minimized test case.\n\n"
            f"Source revision: `{source_commit}`\n\n"
            f"Target: `{target}`\n\n"
            f"SHA-256: `{case['sha256']}`\n\n"
            f"Expected classification: `{case['classification']}`\n\n"
            f"Expected exit code: `{case['exit_code']}`\n\n"
            f"Provisional signature: `{sig}`\n\n"
            "Build the uninstrumented harness from the recorded source revision "
            "using `dotnet publish fuzzing/coverage/DnsParserFuzz/DnsParserFuzz.csproj "
            "-c Release -o /tmp/dns-clean`.\n\n"
            "From this folder, replay the exact input using the clean assembly:\n\n"
            f"`{command.replace('DnsParserFuzz.dll', '/tmp/dns-clean/DnsParserFuzz.dll')}`\n\n"
            "For a strict automated outcome check, from the repository root use:\n\n"
            f"`python3 fuzzing/coverage/reproduce.py --bundle <this-folder> "
            "-- dotnet /tmp/dns-clean/DnsParserFuzz.dll`\n\n"
            "The verifier checks input SHA-256, classification, process exit code "
            "and normalized stack signature. A zero exit from the verifier means "
            "the **expected bug was reproduced**.\n"
        )
        (folder / "README.md").write_text(readme, encoding="utf-8")
        result.append({"signature": sig,
                       "bundle": str(Path("reproducers") / sig),
                       "sha256": case["sha256"],
                       "classification": case["classification"],
                       "candidate_count": len(members)})
    return result


def triage(findings: Path, destination: Path, command: list[str], timeout: float,
           max_candidates: int = MAX_CANDIDATES, target: str | None = None,
           environment_file: Path | None = None) -> dict:
    if not command:
        raise ValueError("replay command is required")
    selected = candidates(findings, max_candidates)
    destination.mkdir(parents=True, exist_ok=True)
    cases = []
    clusters: dict[str, list[str]] = {}
    for kind, sample in selected:
        result = replay(sample, command, timeout, target)
        digest = result["sha256"]
        saved = destination / f"{digest}.bin"
        payload = sample.read_bytes()
        if not saved.exists():
            saved.write_bytes(payload)
        elif saved.read_bytes() != payload:
            raise ValueError("Collision in content-addressed evidence")
        result["source"] = {"kind": kind, "name": sample.name}
        result["evidence"] = saved.name
        clusters.setdefault(result["signature"], []).append(digest)
        cases.append(result)
    source_commit = os.environ.get("GITHUB_SHA", "unknown")
    bundles = write_reproducers(cases, destination, target or "datagram",
                                timeout, source_commit)
    if environment_file is not None and environment_file.is_file():
        shutil.copyfile(environment_file, destination / "environment.txt")
    report = {
        "schema_version": 2,
        "harness": "DnsParserFuzz --replay-target" if target else "DnsParserFuzz --replay",
        "target": target or "datagram",
        "source_commit": source_commit,
        "runtime": "clean-uninstrumented",
        "candidate_count": len(selected),
        "outcomes": {k: sum(x["classification"] == k for x in cases)
                     for k in CLASSIFICATIONS},
        "clusters": [{"signature": sig, "candidate_hashes": sorted(set(hashes))}
                     for sig, hashes in sorted(clusters.items())],
        "cases": cases,
        "reproducers": bundles,
        "environment": "environment.txt" if environment_file is not None and environment_file.is_file() else None,
        "confirmed_defects": 0,
        "note": "Candidates and signatures require human review; no automatic promotion.",
    }
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES)
    parser.add_argument("--target")
    parser.add_argument("--environment-file", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    report = triage(args.findings, args.output, command,
                    args.timeout, args.max_candidates, args.target,
                    args.environment_file)
    print(f"Triaged {report['candidate_count']} AFL++ candidates; "
          f"automatically confirmed defects: {report['confirmed_defects']}")


if __name__ == "__main__":
    main()
