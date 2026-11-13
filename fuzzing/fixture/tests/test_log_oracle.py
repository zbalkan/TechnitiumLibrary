"""Regression tests for the server log oracle."""
import json
import tempfile
import unittest
from pathlib import Path

import log_oracle


class LogOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.baseline = self.root / "baseline"
        self.logs.mkdir()
        self.baseline.mkdir()

    def write(self, content, baseline=""):
        path = self.logs / "2026-11-13.log"
        path.write_text(content)
        if baseline:
            (self.baseline / path.name).write_text(baseline)

    def test_detects_unexpected_exception_with_frames(self):
        self.write("[2026-11-13 12:00:00 UTC] [127.0.0.1:100] [UDP] System.ArgumentOutOfRangeException: Bad length\n"
                   "   at TechnitiumLibrary.Net.Dns.DnsDatagram.ReadFrom(Stream s)\n"
                   "   at DnsServerCore.Dns.DnsServer.ReceiveAsync()\n")
        result = log_oracle.scan(self.logs, self.baseline, [])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["unexpected_exceptions"], 1)
        self.assertEqual(result["exceptions"][0]["type"], "System.ArgumentOutOfRangeException")
        self.assertEqual(len(result["exceptions"][0]["frames"]), 2)

    def test_baseline_is_excluded(self):
        old = "[2026-11-13 11:59:00 UTC] System.InvalidOperationException: Setup\n"
        self.write(old + "[2026-11-13 12:00:00 UTC] Ready\n", old)
        result = log_oracle.scan(self.logs, self.baseline, [])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["records_scanned"], 1)

    def test_allowlist_requires_type_and_message(self):
        self.write("[2026-11-13 12:00:00 UTC] System.FormatException: expected refusal\n")
        rules = [{"type": "System.FormatException", "message_regex": "^expected refusal$",
                  "reason": "Documented expected reject"}]
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, rules)["status"], "passed")
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, [dict(rules[0], message_regex="other")])["status"], "failed")

    def test_missing_logs_fail(self):
        with self.assertRaises(ValueError):
            log_oracle.scan(self.root / "missing", self.baseline, [])

    def test_changed_baseline_fails_closed(self):
        self.write("[2026-11-13 12:00:00 UTC] Something else\n", "different prefix")
        with self.assertRaises(ValueError):
            log_oracle.scan(self.logs, self.baseline, [])

    def test_new_day_log_without_baseline(self):
        self.write("[2026-11-13 12:00:00 UTC] Started\n")
        (self.logs / "2026-11-14.log").write_text("[2026-11-14 00:00:01 UTC] InvalidOperationException: Unexpected\n")
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, [])["unexpected_exceptions"], 1)


if __name__ == "__main__":
    unittest.main()
