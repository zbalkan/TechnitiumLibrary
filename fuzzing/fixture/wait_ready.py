#!/usr/bin/env python3
"""Wait until the Technitium web API accepts a login, or give up."""

from __future__ import annotations

import argparse
import math
import sys
import time
import urllib.error

import tdns


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds to wait")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between attempts")
    args = parser.parse_args(argv)

    if not (math.isfinite(args.timeout) and args.timeout > 0):
        parser.error("--timeout must be positive and finite")
    if not (math.isfinite(args.interval) and args.interval > 0):
        parser.error("--interval must be positive and finite")

    deadline = time.monotonic() + args.timeout
    last_error = "no attempt made"
    while time.monotonic() < deadline:
        try:
            tdns.client_from_env(timeout=max(0.001, deadline - time.monotonic()))
        except (tdns.ApiError, urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last_error = str(exc)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(args.interval, remaining))
            continue
        except (tdns.FixtureError, OSError) as exc:
            # Configuration problems will not fix themselves by waiting.
            print(f"wait_ready: {exc}", file=sys.stderr)
            return 1
        print("wait_ready: API is accepting logins")
        return 0

    print(f"wait_ready: timed out after {args.timeout:.0f}s ({last_error})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
