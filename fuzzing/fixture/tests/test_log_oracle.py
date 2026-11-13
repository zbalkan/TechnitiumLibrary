"""Regression tests for the server log exception oracle."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import log_oracle


PARSER_FRAME = "TechnitiumLibrary.Net.Dns.DnsDatagram.ReadFrom(Stream s) in /src/DnsDatagram.cs:line 250"
REJECTION_RULE = {
    "type": "TechnitiumLibrary.Net.Dns.DnsClientException",
    "terminal_frame_regex": r"TechnitiumLibrary\.Net\.Dns\.DnsDatagram\.ReadFrom\(Stream s\)(?: in .+)?",
    "reason": "Expected malformed DNS wire rejection",
}
PREFIX = "[2026-11-13 12:00:00 UTC] [172.30.0.2:3456] [UDP] "


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

    def rejection(self, message, kind="TechnitiumLibrary.Net.Dns.DnsClientException",
                  frame=PARSER_FRAME):
        return PREFIX + kind + ": " + message + "\n   at " + frame + "\n"

    def test_allows_multiple_known_rejection_messages_without_message_rules(self):
        self.write(self.rejection("compression depth reached") +
                   self.rejection("new record rejection message"))
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["exceptions"]), 2)
        self.assertTrue(all(e["allowed"] for e in result["exceptions"]))

    def test_rejects_wrong_exception_type_even_at_expected_parser_frame(self):
        self.write(self.rejection("index bug", kind="System.IndexOutOfRangeException"))
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["unexpected_exceptions"], 1)

    def test_rejects_expected_type_at_unexpected_location(self):
        self.write(self.rejection("same type, elsewhere",
                                  frame="DnsServerCore.Dns.DnsServer.ProcessRequestAsync()"))
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])["status"], "failed")

    def test_detects_unexpected_exception_with_frames(self):
        self.write(self.rejection("Bad length", kind="System.ArgumentOutOfRangeException",
                                  frame="TechnitiumLibrary.Net.Dns.DnsDatagram.ReadFrom(Stream s)") +
                   "   at DnsServerCore.Dns.DnsServer.ReceiveAsync()\n")
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["unexpected_exceptions"], 1)
        self.assertEqual(result["exceptions"][0]["type"], "System.ArgumentOutOfRangeException")
        self.assertEqual(len(result["exceptions"][0]["frames"]), 2)

    def test_catches_bare_exception_and_system_exception(self):
        self.write(PREFIX + "Exception: boom\n   at Foo.Bar()\n" +
                   PREFIX + "System.Exception: boom\n   at Foo.Bar()\n")
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["unexpected_exceptions"], 2)
        self.assertEqual([e["type"] for e in result["exceptions"]],
                         ["Exception", "System.Exception"])

    def test_inner_exception_cannot_hide_under_approved_outer_exception(self):
        self.write(self.rejection("wrapper")[:-1] +
                   " ---> System.NullReferenceException: broken\n"
                   "   at TechnitiumLibrary.Net.Dns.DnsDatagram.ReadFrom(Stream s)\n")
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(e["type"] == "System.NullReferenceException"
                            and not e["allowed"] for e in result["exceptions"]))

    def test_optional_message_regex_uses_fullmatch(self):
        self.write(self.rejection("unexpected expected text suffix"))
        rule = dict(REJECTION_RULE, message_regex="expected text")
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, [rule])["status"], "failed")
        rule["message_regex"] = "unexpected expected text suffix"
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, [rule])["status"], "passed")

    def test_baseline_is_excluded(self):
        old = "[2026-11-13 11:59:00 UTC] System.InvalidOperationException: Setup\n"
        self.write(old + "[2026-11-13 12:00:00 UTC] Ready\n", old)
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["records_scanned"], 1)

    def test_truncated_baseline_tail_skips_old_entry_without_losing_new_entry(self):
        old = "[2026-11-13 11:59:00 UTC] System.BadException: Old\n   at Caller"
        new = "\n   at Old.Stack()\n" + self.rejection("new rejection")
        self.write(old + new, old)
        result = log_oracle.scan(self.logs, self.baseline, [REJECTION_RULE])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["records_scanned"], 1)
        self.assertEqual(len(result["exceptions"]), 1)

    def test_missing_logs_fail(self):
        with self.assertRaises(ValueError):
            log_oracle.scan(self.root / "missing", self.baseline, [])

    def test_deleted_baseline_log_fails(self):
        (self.baseline / "old.log").write_text("old data")
        self.write("[2026-11-13 12:00:00 UTC] Started\n")
        with self.assertRaisesRegex(ValueError, "disappeared"):
            log_oracle.scan(self.logs, self.baseline, [])

    def test_changed_baseline_fails_closed(self):
        self.write("[2026-11-13 12:00:00 UTC] Something else\n", "different prefix")
        with self.assertRaises(ValueError):
            log_oracle.scan(self.logs, self.baseline, [])

    def test_new_day_log_without_baseline(self):
        self.write("[2026-11-13 12:00:00 UTC] Started\n")
        (self.logs / "2026-11-14.log").write_text(
            "[2026-11-14 00:00:01 UTC] InvalidOperationException: Unexpected\n")
        self.assertEqual(log_oracle.scan(self.logs, self.baseline, [])["unexpected_exceptions"], 1)

    def test_rule_validation_rejects_missing_reason_and_bad_regex(self):
        with self.assertRaises(ValueError):
            log_oracle.validate_rules([{"type": "Exception", "terminal_frame_regex": ".*"}])
        with self.assertRaises(Exception):
            log_oracle.validate_rules([dict(REJECTION_RULE, terminal_frame_regex="(")])

    def test_copy_failure_produces_json_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rule_file = root / "rules.json"
            rule_file.write_text("[]")
            output = root / "result.json"
            with mock.patch("sys.argv", ["log_oracle.py", "--logs", str(self.logs),
                                         "--baseline", str(self.baseline), "--allowlist",
                                         str(rule_file), "--output", str(output),
                                         "--copy-exit", "1"]):
                self.assertEqual(log_oracle.main(), 1)
            result = json.loads(output.read_text())
            self.assertEqual(result["status"], "error")
            self.assertIn("docker cp", result["reason"])


if __name__ == "__main__":
    unittest.main()
