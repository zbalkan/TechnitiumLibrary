#!/usr/bin/env python3
"""Check that a running Technitium DNS Server matches a fuzzing profile.

Three checks, all of which must pass before a fuzzing run may start:
  1. /api/settings/get matches every value in the profile's [settings];
  2. every zone exists with the expected type, signing state and options;
  3. each zone's SOA answers authoritatively over both UDP and TCP, and a
     blocked domain answers NXDOMAIN.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import tdns

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
QTYPE_A = 1

DNSSEC_STATUS = {None: "Unsigned", "NSEC": "SignedWithNSEC", "NSEC3": "SignedWithNSEC3"}


def check_settings(client: tdns.Client, profile: tdns.Profile) -> list[str]:
    actual = client.call("/api/settings/get")["response"]
    return tdns.diff(profile.settings, actual, "settings")


def check_zones(client: tdns.Client, profile: tdns.Profile) -> list[str]:
    problems: list[str] = []
    listed = client.call("/api/zones/list")["response"]["zones"]
    expected_names = {zone.name.lower() for zone in profile.zones}
    for entry in listed:
        if not entry.get("internal", False) and entry["name"].lower() not in expected_names:
            problems.append(f"unexpected authoritative zone: {entry['name']}")
    for zone in profile.zones:
        try:
            actual = client.call("/api/zones/options/get", {"zone": zone.name})["response"]
        except tdns.ApiError as exc:
            problems.append(f"zone {zone.name}: {exc}")
            continue
        nx_proof = zone.sign.get("nxProof", "NSEC") if zone.sign else None
        expected = {"type": zone.type, "dnssecStatus": DNSSEC_STATUS[nx_proof], **zone.options}
        problems.extend(tdns.diff(expected, actual, f"zone {zone.name}"))
    return problems


def _check_soa(zone, host, port) -> list[str]:
    problems = []
    for transport, query in (("udp", tdns.query_udp), ("tcp", tdns.query_tcp)):
        try:
            reply = query(host, port, zone.name, tdns.QTYPE_SOA)
        except (OSError, tdns.FixtureError) as exc:
            problems.append(f"dns {transport} {zone.name} SOA: {exc}")
            continue
        if reply.rcode != RCODE_NOERROR or not reply.aa or tdns.QTYPE_SOA not in reply.answer_types:
            problems.append(
                f"dns {transport} {zone.name} SOA: rcode={reply.rcode} aa={reply.aa} "
                f"answers={reply.ancount}"
            )
    return problems


def _check_blocked(domain, host, port) -> list[str]:
    problems = []
    for transport, query in (("udp", tdns.query_udp), ("tcp", tdns.query_tcp)):
        try:
            reply = query(host, port, domain, QTYPE_A, recursion_desired=True)
        except (OSError, tdns.FixtureError) as exc:
            problems.append(f"dns {transport} {domain} A: {exc}")
            continue
        if reply.rcode != RCODE_NXDOMAIN:
            problems.append(f"dns {transport} {domain} A: blocked domain answered rcode={reply.rcode}")
    return problems


def check_dns(profile: tdns.Profile, host: str, port: int) -> list[str]:
    problems = []
    for zone in profile.zones:
        problems.extend(_check_soa(zone, host, port))
    zone_names = {zone.name for zone in profile.zones}
    for domain in profile.blocked:
        if not any(domain == zone or domain.endswith(f".{zone}") for zone in zone_names):
            problems.extend(_check_blocked(domain, host, port))
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", required=True, type=Path, help="profile TOML file")
    parser.add_argument("--dns-host", default=os.environ.get("FIXTURE_DNS_HOST", "127.0.0.1"))
    parser.add_argument("--dns-port", type=int, default=int(os.environ.get("FIXTURE_DNS_PORT", "53")))
    args = parser.parse_args(argv)

    try:
        profile = tdns.load_profile(args.profile)
        client = tdns.client_from_env()
        problems = check_settings(client, profile)
        problems += check_zones(client, profile)
        problems += check_dns(profile, args.dns_host, args.dns_port)
    except (tdns.ApiError, tdns.FixtureError, OSError) as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return 1

    if problems:
        print(f"verify: {len(problems)} mismatch(es) for profile {profile.name}", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"verify: profile {profile.name} matches ({len(profile.settings)} settings, {len(profile.zones)} zones)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
