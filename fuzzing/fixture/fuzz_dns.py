#!/usr/bin/env python3
"""Deterministic, bounded DNS packet fuzzing. Not coverage-guided."""
import argparse
import json
import random
import socket
import struct
import sys
import time
from pathlib import Path
import tdns

def corpus(seed, count):
    if count < 1:
        raise ValueError("count must be positive")
    rng = random.Random(seed)
    base = tdns.build_query("plain.test", 1, 1)
    samples = [("empty", b""), ("short", b"\0" * 11),
               ("compression-loop", base[:12] + b"\xc0\x0c\x00\x01\x00\x01"),
               ("oversized-label", base[:12] + b"\xff" + base[13:]),
               ("truncated", base[:-1]),
               ("zero-questions", base[:4] + b"\0\0" + base[6:])][:count]
    while len(samples) < count:
        i = len(samples)
        data = bytearray(base)
        variant = rng.randrange(4)
        if variant == 0:
            data = data[:rng.randrange(len(data)+1)]
        elif variant == 1:
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        elif variant == 2:
            data.extend(rng.randbytes(rng.randrange(1, 64)))
        else:
            data = bytearray(rng.randbytes(rng.randrange(1, 256)))
        samples.append((f"mutation-{i:04d}", bytes(data[:4096])))
    return samples

def probe(host, port):
    for proto, query in (("UDP", tdns.query_udp), ("TCP", tdns.query_tcp)):
        try:
            reply = query(host, port, "plain.test", tdns.QTYPE_SOA, timeout=2)
        except (OSError, tdns.FixtureError) as exc:
            return f"{proto}: {exc}"
        if reply.rcode != 0 or not reply.aa or tdns.QTYPE_SOA not in reply.answer_types:
            return f"{proto}: unexpected SOA reply {reply}"
    return None

def _send_udp(host, port, payload, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        try:
            return "response" if sock.recv(65535) else "empty"
        except socket.timeout:
            return "timeout"


def _recv_until(sock, length, deadline):
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        sock.settimeout(remaining)
        part = sock.recv(length - len(result))
        if not part:
            return None
        result.extend(part)
    return bytes(result)


def _send_tcp(host, port, payload, timeout):
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timeout"
            sock.settimeout(remaining)
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            sock.shutdown(socket.SHUT_WR)
            try:
                prefix = _recv_until(sock, 2, deadline)
                if prefix is None:
                    return "closed"
                length = struct.unpack("!H", prefix)[0]
                return "response" if _recv_until(sock, length, deadline) is not None else "closed"
            except socket.timeout:
                return "timeout"
    except (BrokenPipeError, ConnectionResetError) as exc:
        return f"socket-{type(exc).__name__}"


def send(host, port, payload, proto, timeout):
    if proto == "udp":
        return _send_udp(host, port, payload, timeout)
    return _send_tcp(host, port, payload, timeout)


def _record_case(report, host, port, payload, timeout):
    for proto in ("udp", "tcp"):
        report["attempts"] += 1
        try:
            outcome = send(host, port, payload, proto, timeout)
        except OSError as exc:
            outcome = f"socket-{type(exc).__name__}"
        else:
            if not outcome.startswith("socket-"):
                report["packets_sent"] += 1
        key = f"{proto}:{outcome}"
        report["outcomes"][key] = report["outcomes"].get(key, 0) + 1


def _health_failure(phase, reason, name, payload):
    return {"phase": phase, "case": name, "packet_hex": payload.hex(),
            "reason": reason}


def run(host, port, seed, count, interval, timeout):
    if interval < 1 or timeout <= 0:
        raise ValueError("interval and timeout must be positive")
    report = {"status": "passed", "seed": seed, "count": count,
              "packets_sent": 0, "attempts": 0, "outcomes": {}, "failure": None}
    reason = probe(host, port)
    if reason:
        report.update(status="failed", failure={"phase": "baseline", "reason": reason})
        return report
    last_case = None
    for index, (name, payload) in enumerate(corpus(seed, count), 1):
        last_case = (name, payload)
        _record_case(report, host, port, payload, timeout)
        if index % interval == 0:
            reason = probe(host, port)
            if reason:
                report.update(status="failed",
                              failure=_health_failure("health", reason, name, payload))
                return report
    reason = probe(host, port)
    if reason:
        report.update(status="failed",
                      failure=_health_failure("final", reason, *last_case))
    return report

def main(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--seed", type=int, default=20261106)
    p.add_argument("--count", type=int, default=80)
    p.add_argument("--interval", type=int, default=10)
    p.add_argument("--timeout", type=float, default=0.15)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        report = run(args.host, args.port, args.seed, args.count, args.interval, args.timeout)
    except (ValueError, OSError, tdns.FixtureError) as exc:
        report = {"status": "failed", "seed": args.seed, "count": args.count,
                  "failure": {"phase": "runner", "reason": str(exc)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"fuzz: {report['status']}, {report.get('packets_sent', 0)} packets")
    if report.get("failure"):
        print(report["failure"], file=sys.stderr)
    return int(report["status"] != "passed")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
