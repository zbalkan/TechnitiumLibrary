#!/usr/bin/env python3
"""Detect unexpected .NET exception records added to Technitium DNS Server logs."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ENTRY = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (UTC|Local)\] ")
EXCEPTION = re.compile(r"(?<![\w.])((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*(?:Exception|Error)):\s*(.*)")
FRAME = re.compile(r"^\s*at\s+(.+)")
MAX_LOG_BYTES = 16 * 1024 * 1024


def added_text(now: Path, before: Path | None) -> str:
    data = now.read_bytes()
    if len(data) > MAX_LOG_BYTES:
        raise ValueError(f"Log exceeds safety limit: {now.name}")
    if before is not None and before.exists():
        original = before.read_bytes()
        if not data.startswith(original):
            raise ValueError(f"Log changed before baseline boundary: {now.name}")
        data = data[len(original):]
    return data.decode("utf-8", errors="replace")


def entries(text: str):
    record = []
    for line in text.splitlines():
        if ENTRY.match(line):
            if record:
                yield record
            record = [line]
        elif record:
            record.append(line)
        elif line.strip():
            raise ValueError("Log begins with an incomplete entry")
    if record:
        yield record


def scan(log_dir: Path, baseline_dir: Path, allowlist: list[dict]) -> dict:
    if not log_dir.is_dir():
        raise ValueError(f"Server log directory missing: {log_dir}")
    files = sorted(log_dir.glob("*.log"))
    if not files:
        raise ValueError("No server log files found")
    findings = []
    records = 0
    for path in files:
        baseline = baseline_dir / path.name
        for record in entries(added_text(path, baseline)):
            records += 1
            for index, line in enumerate(record):
                match = EXCEPTION.search(line)
                if not match:
                    continue
                kind, message = match.groups()
                permitted = next((rule for rule in allowlist
                                  if rule["type"] == kind
                                  and re.search(rule["message_regex"], message)), None)
                findings.append({
                    "log": path.name,
                    "timestamp": ENTRY.match(record[0]).group(1),
                    "timezone": ENTRY.match(record[0]).group(2),
                    "type": kind,
                    "message": message,
                    "frames": [m.group(1) for tail in record[index + 1:]
                               if (m := FRAME.match(tail))][:5],
                    "allowed": permitted is not None,
                    "reason": permitted["reason"] if permitted else None,
                })
    unexpected = sum(not item["allowed"] for item in findings)
    return {"status": "failed" if unexpected else "passed",
            "records_scanned": records, "exceptions": findings,
            "unexpected_exceptions": unexpected}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        rules = json.loads(args.allowlist.read_text())
        if not isinstance(rules, list) or any(
            not isinstance(rule, dict) or
            set(rule) != {"type", "message_regex", "reason"} or
            not all(isinstance(value, str) and value for value in rule.values())
            for rule in rules
        ):
            raise ValueError("Every allowlist entry needs type, message_regex and reason")
        result = scan(args.logs, args.baseline, rules)
    except (OSError, ValueError, re.error) as error:
        result = {"status": "error", "reason": str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Server log oracle: {result['status']}; unexpected={result.get('unexpected_exceptions', 'unknown')}")
    return int(result["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
