"""Behaviour tests for the fuzzing fixture scripts.

Run from fuzzing/fixture:  python -m unittest discover -s tests -t . -v

The HTTP API and DNS listeners are local fakes written from APIDOCS.md (see
stub_server.py). The fuzz-fixture workflow runs the same scripts against a
real server; these tests cover the scripts' own logic only.
"""

from __future__ import annotations

import contextlib
import io
import os
import socket
import time
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import provision
import restore
import tdns
import verify
import wait_ready
from tests import stub_server

FIXTURE_DIR = Path(__file__).resolve().parent.parent
BASE = FIXTURE_DIR / "profiles" / "base.toml"
PASSWORD = "stub-admin-password"
FIXTURE_ENV = {
    "FIXTURE_API_PASSWORD": PASSWORD,
    "FIXTURE_TSIG_SECRET": "c3R1Yi10c2lnLXNlY3JldA==",
    "FIXTURE_FUZZER_NET": "172.30.0.0/24",
}


def run_cli(main, argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class SerialisationTests(unittest.TestCase):
    """Formats documented under 'Set DNS Settings' and 'Set Zone Options'."""

    def test_qpm_limits_are_pipe_separated_rows(self):
        rows = [{"prefix": 32, "udpLimit": 600, "tcpLimit": 600},
                {"prefix": 24, "udpLimit": 6000, "tcpLimit": 6000}]
        value = tdns.to_form_value("qpmPrefixLimitsIPv4", rows, tdns.CLEARABLE_SETTINGS)
        self.assertEqual(value, "32|600|600|24|6000|6000")

    def test_tsig_keys_are_name_secret_algorithm_rows(self):
        rows = [{"keyName": "k", "sharedSecret": "s+/=", "algorithmName": "hmac-sha256"}]
        value = tdns.to_form_value("tsigKeys", rows, tdns.CLEARABLE_SETTINGS)
        self.assertEqual(value, "k|s+/=|hmac-sha256")

    def test_update_policy_types_are_comma_separated_inside_a_row(self):
        rows = [{"tsigKeyName": "k", "domain": "*.z", "allowedTypes": ["A", "TXT"]}]
        value = tdns.to_form_value("updateSecurityPolicies", rows, tdns.CLEARABLE_ZONE_OPTIONS)
        self.assertEqual(value, "k|*.z|A,TXT")

    def test_empty_clearable_list_is_sent_as_false(self):
        # The API removes all entries only when it receives the literal "false".
        self.assertEqual(tdns.to_form_value("forwarders", [], tdns.CLEARABLE_SETTINGS), "false")

    def test_empty_non_clearable_list_is_sent_as_empty_string(self):
        value = tdns.to_form_value("dnsReverseProxyNetworkACL", [], tdns.CLEARABLE_SETTINGS)
        self.assertEqual(value, "")

    def test_scalar_lists_and_booleans(self):
        cases = [("dnsServerLocalEndPoints", ["0.0.0.0:53", "[::]:53"], "0.0.0.0:53,[::]:53"),
                 ("saveCache", False, "false"), ("enableBlocking", True, "true"),
                 ("udpPayloadSize", 1232, "1232")]
        for key, value, expected in cases:
            with self.subTest(key=key):
                self.assertEqual(tdns.to_form_value(key, value, tdns.CLEARABLE_SETTINGS), expected)


class ProfileTests(unittest.TestCase):
    def test_blocking_profile_allows_recursion_only_for_fixture_clients(self):
        with mock.patch.dict(os.environ, FIXTURE_ENV):
            profile = tdns.load_profile(BASE)
        self.assertEqual(profile.settings["recursion"], "UseSpecifiedNetworkACL")
        self.assertEqual(profile.settings["recursionNetworkACL"],
                         ["127.0.0.1", FIXTURE_ENV["FIXTURE_FUZZER_NET"]])
        self.assertIs(profile.settings["locallyServedDnsZones"], False)

    def test_secret_comes_from_environment(self):
        with mock.patch.dict(os.environ, FIXTURE_ENV):
            profile = tdns.load_profile(BASE)
        self.assertEqual(profile.settings["tsigKeys"][0]["sharedSecret"],
                         FIXTURE_ENV["FIXTURE_TSIG_SECRET"])

    def test_missing_secret_is_reported(self):
        env = {k: v for k, v in FIXTURE_ENV.items() if k != "FIXTURE_TSIG_SECRET"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(tdns.FixtureError, "FIXTURE_TSIG_SECRET"):
                tdns.load_profile(BASE)

    def test_cycle_with_relative_parent_normalizes_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "cycle.toml"
            first.write_text('[meta]\nextends = "./subdir/../cycle.toml"\n')
            (Path(tmp) / "subdir").mkdir()
            with self.assertRaisesRegex(tdns.FixtureError, "inheritance loop"):
                tdns.load_profile(first)

    def test_zone_options_for_unknown_zone_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.toml"
            bad.write_text(f'[meta]\nextends = "{BASE}"\n[zone_options."missing.test"]\nupdate = "Allow"\n')
            with mock.patch.dict(os.environ, FIXTURE_ENV):
                with self.assertRaisesRegex(tdns.FixtureError, "missing.test"):
                    tdns.load_profile(bad)


class ReadinessTests(unittest.TestCase):
    def test_negative_interval_is_rejected(self):
        with self.assertRaises(SystemExit):
            wait_ready.main(["--interval", "-1"])

    def test_short_deadline_is_forwarded_to_http_client(self):
        observed = []
        def attempt(*, timeout):
            observed.append(timeout)
            raise tdns.ApiError("not ready")

        with mock.patch.object(tdns, "client_from_env", side_effect=attempt):
            code, _, _ = run_cli(wait_ready.main,
                                 ["--timeout", "0.02", "--interval", "0.01"])
        self.assertEqual(code, 1)
        self.assertTrue(observed)
        self.assertTrue(all(0 < value <= 0.02 for value in observed))


class DiffTests(unittest.TestCase):
    def test_null_empty_string_and_empty_list_are_equal(self):
        expected = {"a": [], "b": "", "c": []}
        actual = {"a": None, "b": None, "c": ""}
        self.assertEqual(tdns.diff(expected, actual, "s"), [])

    def test_changed_value_is_reported_with_both_sides(self):
        problems = tdns.diff({"recursion": "Deny"}, {"recursion": "Allow"}, "settings")
        self.assertEqual(problems, ["settings.recursion: expected 'Deny', server has 'Allow'"])

    def test_key_absent_from_server_is_reported(self):
        problems = tdns.diff({"proxyType": "None"}, {}, "settings")
        self.assertEqual(len(problems), 1)
        self.assertIn("settings.proxyType: not reported", problems[0])


class DnsQueryTests(unittest.TestCase):
    def test_authoritative_query_clears_rd(self):
        query = tdns.build_query("plain.test", tdns.QTYPE_SOA, 0x1234)
        self.assertEqual(struct.unpack("!H", query[2:4])[0] & 0x0100, 0)

    def test_query_shaped_packet_cannot_pass_health_probe(self):
        query = tdns.build_query("plain.test", tdns.QTYPE_SOA, 0x1234)
        with self.assertRaises(tdns.FixtureError):
            tdns.parse_reply_header(query)

    def test_fake_soa_response_has_valid_answer(self):
        fake = stub_server.FakeTechnitium("admin", PASSWORD)
        fake.zones["plain.test"] = {"name": "plain.test"}
        query = tdns.build_query("plain.test", tdns.QTYPE_SOA, 0x1234)
        reply = tdns.parse_reply_header(stub_server.dns_answer(fake, query))
        self.assertEqual(reply.answer_types, (tdns.QTYPE_SOA,))

    def test_soa_reply_rejects_truncated_rdata(self):
        fake = stub_server.FakeTechnitium("admin", PASSWORD)
        fake.zones["plain.test"] = {"name": "plain.test"}
        query = tdns.build_query("plain.test", tdns.QTYPE_SOA, 0x1234)
        response = stub_server.dns_answer(fake, query)
        with self.assertRaises(tdns.FixtureError):
            tdns.parse_reply_header(response[:-1])

    def test_blocked_query_sets_rd(self):
        query = tdns.build_query("blocked.fuzz.test", 1, 0x1234,
                                recursion_desired=True)
        self.assertEqual(struct.unpack("!H", query[2:4])[0] & 0x0100, 0x0100)

    def test_container_network_is_internal(self):
        workflow = (FIXTURE_DIR.parent.parent / ".github" / "workflows"
                    / "fuzz-fixture.yml").read_text(encoding="utf-8")
        self.assertIn('docker network create --internal --subnet "${FUZZ_SUBNET}" fuzznet',
                      workflow)


class EndToEndTests(unittest.TestCase):
    """provision -> verify -> restore against the local fakes."""

    def setUp(self):
        self.fake = stub_server.FakeTechnitium("admin", PASSWORD)
        self.api, url = stub_server.start_api(self.fake)
        self.dns, self.dns_port = stub_server.start_dns(self.fake)
        self.tmp = tempfile.TemporaryDirectory()
        self.backup = Path(self.tmp.name) / "fixture-backup.zip"
        env = {**FIXTURE_ENV, "FIXTURE_API_URL": url,
               "FIXTURE_DNS_HOST": "127.0.0.1", "FIXTURE_DNS_PORT": str(self.dns_port)}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.api.shutdown()
        self.api.server_close()
        for server in self.dns:
            server.shutdown()
            server.server_close()
        self.tmp.cleanup()

    def provision(self, profile: Path = BASE):
        return run_cli(provision.main, ["--profile", str(profile), "--backup", str(self.backup)])

    def test_fragmented_tcp_length_and_payload_are_accepted(self):
        self.provision()
        packet = tdns.build_query("plain.test", tdns.QTYPE_SOA, 0x1234)
        frame = struct.pack("!H", len(packet)) + packet
        with socket.create_connection(("127.0.0.1", self.dns_port), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(frame[:1])
            time.sleep(0.01)
            sock.sendall(frame[1:6])
            time.sleep(0.01)
            sock.sendall(frame[6:])
            prefix = tdns._recv_exact(sock, 2)
            size = struct.unpack("!H", prefix)[0]
            reply = tdns.parse_reply_header(tdns._recv_exact(sock, size))
        self.assertEqual(reply.answer_types, (tdns.QTYPE_SOA,))

    def test_zone_exists_propagates_server_errors(self):
        self.fake.fail_paths.add("/api/zones/options/get")
        client = tdns.client_from_env()
        with self.assertRaises(tdns.ApiError):
            provision.zone_exists(client, "plain.test")

    def test_provisioned_base_profile_verifies(self):
        code, _, err = self.provision()
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(verify.main, ["--profile", str(BASE)])
        self.assertEqual(code, 0, err)
        self.assertIn("matches", out)

    def test_zones_are_signed_as_profiled(self):
        self.provision()
        status = {name: z["dnssecStatus"] for name, z in self.fake.zones.items()}
        self.assertEqual(status, {"plain.test": "Unsigned", "nsec.test": "SignedWithNSEC",
                                  "nsec3.test": "SignedWithNSEC3",
                                  "2.0.192.in-addr.arpa": "Unsigned"})

    def test_reprovisioning_recreates_existing_zones(self):
        self.provision()
        code, _, err = self.provision()
        self.assertEqual(code, 0, err)

    def test_error_status_in_http_200_fails_provisioning(self):
        # The API reports errors in the JSON body, not the HTTP status.
        self.fake.fail_paths.add("/api/zones/dnssec/sign")
        code, _, err = self.provision()
        self.assertEqual(code, 1)
        self.assertIn("injected failure on /api/zones/dnssec/sign", err)

    def test_wrong_password_fails_provisioning(self):
        with mock.patch.dict(os.environ, {"FIXTURE_API_PASSWORD": "wrong"}):
            code, _, err = self.provision()
        self.assertEqual(code, 1)
        self.assertIn("Invalid username or password", err)

    def test_setting_drift_fails_verification(self):
        self.provision()
        self.fake.settings["recursion"] = "Allow"
        code, _, err = run_cli(verify.main, ["--profile", str(BASE)])
        self.assertEqual(code, 1)
        self.assertIn("settings.recursion: expected 'UseSpecifiedNetworkACL', server has 'Allow'", err)

    def test_zone_option_drift_fails_verification(self):
        self.provision()
        self.fake.zones["plain.test"]["notify"] = "ZoneNameServers"
        code, _, err = run_cli(verify.main, ["--profile", str(BASE)])
        self.assertEqual(code, 1)
        self.assertIn("zone plain.test.notify", err)

    def test_disabled_blocking_is_not_confused_with_special_test_zone(self):
        self.provision()
        self.fake.settings["enableBlocking"] = False
        with mock.patch.dict(os.environ, FIXTURE_ENV):
            profile = tdns.load_profile(BASE)
        problems = verify.check_dns(profile, "127.0.0.1", self.dns_port)
        self.assertTrue(any("blocked.fuzz.test" in item and "rcode=5" in item
                            for item in problems), problems)

    def test_unanswered_zone_fails_dns_check(self):
        self.provision()
        # Deleting the zone behind the API makes the listener refuse the SOA query.
        del self.fake.zones["nsec3.test"]
        code, _, err = run_cli(verify.main, ["--profile", str(BASE)])
        self.assertEqual(code, 1)
        self.assertIn("dns udp nsec3.test SOA: rcode=5", err)
        self.assertIn("dns tcp nsec3.test SOA: rcode=5", err)

    def test_backup_is_written_and_restorable(self):
        self.provision()
        self.assertTrue(self.backup.read_bytes().startswith(b"PK"))
        code, _, err = run_cli(restore.main, ["--backup", str(self.backup), "--flush-cache"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.restored, [self.backup.read_bytes()])
        self.assertEqual(self.fake.calls[-1], "/api/cache/flush")


if __name__ == "__main__":
    unittest.main()
