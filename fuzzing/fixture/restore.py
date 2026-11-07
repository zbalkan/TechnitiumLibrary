#!/usr/bin/env python3
"""Restore a fixture backup into a running Technitium DNS Server.

Used between fuzzing rounds to reset zone and cache-related state. Logs in
fresh on every call, since session tokens expire (30 minutes by default).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import tdns
from provision import BACKUP_ITEMS


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", required=True, type=Path, help="backup zip from provision.py")
    parser.add_argument("--flush-cache", action="store_true", help="also flush the DNS cache")
    args = parser.parse_args(argv)

    query = {**BACKUP_ITEMS, "deleteExistingFiles": "true"}
    try:
        data = args.backup.read_bytes()
        client = tdns.client_from_env()
        client.call_upload("/api/settings/restore", query, "file", args.backup.name, data)
        if args.flush_cache:
            client.call("/api/cache/flush")
    except (tdns.ApiError, tdns.FixtureError, OSError) as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    print(f"restore: {args.backup} applied")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
