"""DNS fuzzing corpus and failure-oracle regression tests."""
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import fuzz_dns
import tdns

class CorpusTests(unittest.TestCase):
    def test_reproducible(self):
        samples = fuzz_dns.corpus(19, 50)
        payloads = b"".join(struct.pack("!H", len(data)) + data for _, data in samples)
        self.assertEqual(
            hashlib.sha256(payloads).hexdigest(),
            "d312f929d2a7b7197480a4f97cdb160221dc19118129a69b6ed9c2b8631fc45b",
        )
    def test_seed_changes_mutations(self):
        self.assertNotEqual(fuzz_dns.corpus(19, 50), fuzz_dns.corpus(20, 50))
    def test_count_and_bounds(self):
        for count in (1, 6, 7, 30):
            data = fuzz_dns.corpus(1, count)
            self.assertEqual(len(data), count)
            self.assertTrue(all(len(p) <= 4096 for _, p in data))
    def test_malformed_seeds(self):
        data = dict(fuzz_dns.corpus(1, 8))
        self.assertEqual(data["empty"], b"")
        self.assertEqual(len(data["short"]), 11)
        self.assertIn("compression-loop", data)
    def test_invalid_count(self):
        with self.assertRaises(ValueError):
            fuzz_dns.corpus(1, 0)

class CampaignTests(unittest.TestCase):
    def test_drops_are_not_failures(self):
        with mock.patch.object(fuzz_dns, "probe", return_value=None), \
             mock.patch.object(fuzz_dns, "send", return_value="timeout"):
            report = fuzz_dns.run("127.0.0.1", 53, 1, 4, 2, 0.01)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["packets_sent"], 8)
        self.assertEqual(report["outcomes"]["udp:timeout"], 4)
        self.assertEqual(report["outcomes"]["tcp:timeout"], 4)
    def test_health_failure_records_trigger(self):
        with mock.patch.object(fuzz_dns, "probe", side_effect=[None, "offline"]), \
             mock.patch.object(fuzz_dns, "send", return_value="timeout"):
            report = fuzz_dns.run("127.0.0.1", 53, 1, 4, 1, 0.01)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failure"]["phase"], "health")
        self.assertEqual(report["failure"]["case"], "empty")
        self.assertEqual(report["failure"]["packet_hex"], "")
    def test_final_health_failure_retains_last_packet(self):
        with mock.patch.object(fuzz_dns, "probe", side_effect=[None, "offline"]), \
             mock.patch.object(fuzz_dns, "send", return_value="timeout"):
            report = fuzz_dns.run("127.0.0.1", 53, 1, 4, 10, 0.01)
        self.assertEqual(report["failure"]["phase"], "final")
        self.assertEqual(report["failure"]["case"], "oversized-label")
        self.assertEqual(report["failure"]["packet_hex"],
                         dict(fuzz_dns.corpus(1, 4))["oversized-label"].hex())

    def test_socket_failures_are_attempts_not_packets(self):
        with mock.patch.object(fuzz_dns, "probe", return_value=None), \
             mock.patch.object(fuzz_dns, "send", side_effect=OSError("connect")):
            report = fuzz_dns.run("127.0.0.1", 53, 1, 2, 3, 0.01)
        self.assertEqual(report["attempts"], 4)
        self.assertEqual(report["packets_sent"], 0)

    def test_probes_reject_non_soa_replies(self):
        response = tdns.DnsReply(txid=1, aa=True, rcode=0,
                                 ancount=1, answer_types=(1,))
        with mock.patch.object(tdns, "query_udp", return_value=response):
            self.assertIn("unexpected SOA", fuzz_dns.probe("127.0.0.1", 53))

    def test_initial_failure_stops(self):
        with mock.patch.object(fuzz_dns, "probe", return_value="offline"):
            report = fuzz_dns.run("127.0.0.1", 53, 1, 4, 1, 0.01)
        self.assertEqual(report["packets_sent"], 0)
        self.assertEqual(report["status"], "failed")
    def test_cli_writes_evidence_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with mock.patch.object(fuzz_dns, "probe", return_value="offline"):
                rc = fuzz_dns.main(["--output", str(path)])
            self.assertEqual(rc, 1)
            self.assertEqual(json.loads(path.read_text())["failure"]["reason"], "offline")
