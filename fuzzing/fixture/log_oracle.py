#!/usr/bin/env python3
"""Classify exceptions written during a Technitium DNS Server fuzz campaign."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ENTRY = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (UTC|Local)\] ")
# Match bare Exception and System.Exception as well as concrete *Exception / *Error types.
EXCEPTION = re.compile(
    r"(?<![\w.])((?:[A-Za-z_]\w*\.)*(?:[A-Za-z_]\w*(?:Exception|Error)|Exception|Error)):[ \t]*(.*)"
)
FRAME = re.compile(r"^\s*at\s+(.+)")
MAX_LOG_BYTES = 16 * 1024 * 1024


def added_text(now: Path, baseline: Path | None) -> str:
    data = now.read_bytes()
    if len(data) > MAX_LOG_BYTES:
        raise ValueError(f"Log exceeds safety limit: {now.name}")
    if baseline is None or not baseline.exists():
        return data.decode("utf-8", errors="replace")
    original = baseline.read_bytes()
    if not data.startswith(original):
        raise ValueError(f"Log changed before baseline boundary: {now.name}")
    delta = data[len(original):].decode("utf-8", errors="replace")
    if not original:
        return delta

    # A docker cp can snapshot the middle of a multi-line log entry. Ignore
    # any continuation of that pre-campaign entry, and resume at the first
    # complete NEW timestamped entry. Never classify the old tail as a case.
    offset = 0
    for line in delta.splitlines(keepends=True):
        if ENTRY.match(line):
            return delta[offset:]
        offset += len(line)
    return ""


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
            raise ValueError("New log begins with an incomplete entry")
    if record:
        yield record


def validate_rules(rules: object) -> list[dict]:
    if not isinstance(rules, list):
        raise ValueError("Allowlist must be a JSON list")
    for rule in rules:
        required = {"type", "terminal_frame_regex", "reason"}
        optional = {"message_regex"}
        if (not isinstance(rule, dict) or
                not required.issubset(rule) or
                not set(rule).issubset(required | optional) or
                not all(isinstance(value, str) and value for value in rule.values())):
            raise ValueError("Each allowlist rule needs type, terminal_frame_regex and reason; message_regex is optional")
        re.compile(rule["terminal_frame_regex"])
        if "message_regex" in rule:
            re.compile(rule["message_regex"])
    return rules


def classify(kind: str, message: str, frames: list[str], rules: list[dict]) -> dict | None:
    if not frames:
        return None
    for rule in rules:
        if kind != rule["type"]:
            continue
        if re.fullmatch(rule["terminal_frame_regex"], frames[-1]) is None:
            continue
        if "message_regex" in rule and re.fullmatch(rule["message_regex"], message) is None:
            continue
        return rule
    return None


def scan(log_dir: Path, baseline_dir: Path, allowlist: list[dict]) -> dict:
    rules = validate_rules(allowlist)
    if not baseline_dir.is_dir():
        raise ValueError(f"Missing pre-campaign log baseline: {baseline_dir}")
    if not log_dir.is_dir():
        raise ValueError(f"Server log directory missing: {log_dir}")
    files = sorted(log_dir.glob("*.log"))
    if not files:
        raise ValueError("No server log files found")
    missing = {p.name for p in baseline_dir.glob("*.log")} - {p.name for p in files}
    if missing:
        raise ValueError(f"Pre-campaign log file disappeared: {', '.join(sorted(missing))}")
    findings = []
    records = 0
    for path in files:
        baseline = baseline_dir / path.name
        for record in entries(added_text(path, baseline if baseline.exists() else None)):
            records += 1
            headers = [(index, match) for index, line in enumerate(record)
                       if (match := EXCEPTION.search(line))]
            for position, (index, match) in enumerate(headers):
                end = headers[position + 1][0] if position + 1 < len(headers) else len(record)
                kind, message = match.groups()
                frames = [m.group(1) for line in record[index + 1:end]
                          if (m := FRAME.match(line))]
                allowed = classify(kind, message, frames, rules)
                findings.append({
                    "log": path.name,
                    "timestamp": ENTRY.match(record[0]).group(1),
                    "timezone": ENTRY.match(record[0]).group(2),
                    "type": kind, "message": message,
                    "frames": frames[:5], "terminal_frame": frames[-1] if frames else None,
                    "allowed": allowed is not None,
                    "reason": allowed["reason"] if allowed else None,
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
    parser.add_argument("--copy-exit", type=int, default=0,
                        help="Exit status from docker cp; nonzero always fails the oracle")
    args = parser.parse_args()
    try:
        if args.copy_exit != 0:
            raise ValueError(f"Failed to copy server logs: docker cp exited {args.copy_exit}")
        rules = validate_rules(json.loads(args.allowlist.read_text()))
        result = scan(args.logs, args.baseline, rules)
    except (OSError, ValueError, re.error) as error:
        result = {"status": "error", "reason": str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Server log oracle: {result['status']}; unexpected={result.get('unexpected_exceptions', 'unknown')}")
    return int(result["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
