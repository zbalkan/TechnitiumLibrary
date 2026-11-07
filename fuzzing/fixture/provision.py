#!/usr/bin/env python3
"""Apply a fuzzing profile to a running Technitium DNS Server.

Order: DNS settings, then zones (recreate, import, sign, options), then
blocked domains, then an optional settings backup. Any API error stops the
run with a non-zero exit code.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import tdns

BACKUP_ITEMS = {
    "dnsSettings": "true",
    "logSettings": "true",
    "zones": "true",
    "allowedZones": "true",
    "blockedZones": "true",
    # The container's admin password comes from its environment; restoring
    # an auth config would override it, so it is left out of the backup.
    "authConfig": "false",
    "apps": "false",
}


def apply_settings(client: tdns.Client, profile: tdns.Profile) -> None:
    client.call("/api/settings/set", tdns.settings_form(profile))
    print(f"settings: applied {len(profile.settings) + len(profile.settings_write_only)} values")


def zone_exists(client: tdns.Client, name: str) -> bool:
    try:
        client.call("/api/zones/options/get", {"zone": name})
    except tdns.ApiError as exc:
        if "No such zone was found" not in str(exc):
            raise
        return False
    return True


def apply_zone(client: tdns.Client, zone: tdns.Zone) -> None:
    if zone_exists(client, zone.name):
        client.call("/api/zones/delete", {"zone": zone.name})
    client.call("/api/zones/create", {"zone": zone.name, "type": zone.type})

    if zone.file is not None:
        text = zone.file.read_text(encoding="utf-8")
        client.call_text(
            "/api/zones/import",
            {"zone": zone.name, "overwrite": "true", "overwriteZone": "false"},
            text,
        )

    if zone.sign:
        params = {k: tdns.to_form_value(k, v, frozenset()) for k, v in zone.sign.items()}
        params["zone"] = zone.name
        client.call("/api/zones/dnssec/sign", params)

    if zone.options:
        client.call("/api/zones/options/set", tdns.zone_options_form(zone))

    state = "signed" if zone.sign else "unsigned"
    print(f"zone {zone.name}: created, {state}, {len(zone.options)} options")


def apply_blocked(client: tdns.Client, domains: list[str]) -> None:
    for domain in domains:
        client.call("/api/blocked/add", {"domain": domain})
    print(f"blocked: {len(domains)} domains")


def write_backup(client: tdns.Client, path: Path) -> None:
    data = client.download("/api/settings/backup", BACKUP_ITEMS)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"backup: {path} ({len(data)} bytes)")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path, help="profile TOML file")
    parser.add_argument("--backup", type=Path, help="write a settings backup zip here")
    args = parser.parse_args(argv)

    try:
        profile = tdns.load_profile(args.profile)
        client = tdns.client_from_env()
        print(f"profile: {profile.name}")
        apply_settings(client, profile)
        for zone in profile.zones:
            apply_zone(client, zone)
        apply_blocked(client, profile.blocked)
        if args.backup:
            write_backup(client, args.backup)
    except (tdns.ApiError, tdns.FixtureError, OSError) as exc:
        print(f"provision failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
