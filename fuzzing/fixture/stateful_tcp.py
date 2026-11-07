#!/usr/bin/env python3
"""Bounded stateful DNS-over-TCP framing and connection recovery probes."""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

import fuzz_dns
import tdns


def frame(packet: bytes) -> bytes:
    if len(packet) > 65535:
        raise ValueError("DNS TCP payload exceeds 65535 bytes")
    return struct.pack("!H", len(packet)) + packet


def recv_frame(sock, deadline: float, expected_id: bytes | None) -> str:
    prefix = fuzz_dns._recv_until(sock, 2, deadline)
    if prefix is None:
        return "closed"
    length = struct.unpack("!H", prefix)[0]
    if length == 0:
        return "empty"
    data = fuzz_dns._recv_until(sock, length, deadline)
    if data is None:
        return "closed"
    if expected_id is not None and data[:2] != expected_id:
        return "unexpected-id"
    return "response"


def send_fragments(sock, chunks: list[bytes]) -> None:
    for chunk in chunks:
        sock.sendall(chunk)
        # Deliberate application write fragmentation; the transport may coalesce.
        time.sleep(0.002)


def _exercise(host: str, port: int, mode: str, timeout: float, query: bytes) -> str:
    deadline = time.monotonic() + timeout
    full = frame(query)
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            if mode == "fragmented":
                send_fragments(conn, [full[:1], full[1:2], full[2:4],
                                      full[4:9], full[9:]])
                return recv_frame(conn, deadline, query[:2])
            if mode == "sequential":
                conn.sendall(full)
                first = recv_frame(conn, deadline, query[:2])
                if first != "response":
                    return f"first-{first}"
                conn.sendall(full)
                return "second-" + recv_frame(conn, deadline, query[:2])
            if mode == "pipelined":
                conn.sendall(full + full)
                first = recv_frame(conn, deadline, query[:2])
                if first != "response":
                    return f"first-{first}"
                return "second-" + recv_frame(conn, deadline, query[:2])
            if mode == "partial-prefix":
                conn.sendall(full[:1])
            elif mode == "partial-body":
                conn.sendall(struct.pack("!H", len(query) + 8) + query)
            elif mode == "zero-length":
                conn.sendall(b"\x00\x00")
            else:
                raise ValueError(f"Unsupported stateful TCP scenario: {mode}")
            conn.shutdown(socket.SHUT_WR)
            return "incomplete-sent"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except OSError as exc:
        return f"socket-{type(exc).__name__}"


SCENARIOS = ("fragmented", "sequential", "pipelined", "partial-prefix",
             "partial-body", "zero-length")


def run(host: str, port: int, timeout: float = 2) -> dict:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    report = {"status": "passed", "scenarios": {}, "failure": None}
    initial = fuzz_dns.probe(host, port)
    if initial:
        report.update(status="failed", failure={"phase": "baseline", "reason": initial})
        return report
    query = tdns.build_query("plain.test", tdns.QTYPE_SOA, 1)
    for scenario in SCENARIOS:
        outcome = _exercise(host, port, scenario, timeout, query)
        report["scenarios"][scenario] = outcome
        expected = {"fragmented": "response", "sequential": "second-response",
                    "pipelined": "second-response"}.get(scenario)
        if expected is not None and outcome != expected:
            report.update(status="failed", failure={
                "phase": scenario, "scenario": scenario, "reason": outcome})
            return report
        health = fuzz_dns.probe(host, port)
        if health:
            report.update(status="failed", failure={
                "phase": "recovery", "scenario": scenario, "reason": health})
            return report
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = run(args.host, args.port, args.timeout)
    except (OSError, ValueError, tdns.FixtureError) as exc:
        report = {"status": "failed", "failure": {"phase": "runner", "reason": str(exc)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(f"stateful TCP: {report['status']}; scenarios={len(report.get('scenarios', {}))}")
    if report.get("failure"):
        print(report["failure"], file=sys.stderr)
    return int(report["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
