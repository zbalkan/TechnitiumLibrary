"""Tests for the live network-path negative control, without real sockets or Docker."""
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import network_negative_control as negative


class NegativeControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.baseline = self.root / "baseline"
        self.logs.mkdir()
        self.baseline.mkdir()
        self.rules = [{
            "type": negative.CONTROL_TYPE,
            "terminal_frame_regex":
                r"TechnitiumLibrary\.Net\.Dns\.DnsDatagram\.ReadFrom\(Stream s\)(?: in .+)?",
            "reason": "Expected rejection stored by the DNS parser",
        }]

    def write_log(self, kind=None, message=None, frame=None):
        kind = kind or negative.CONTROL_TYPE
        message = message or negative.CONTROL_MESSAGE
        frame = frame or "TechnitiumLibrary.Net.Dns.DnsDatagram.ReadFrom(Stream s)"
        (self.logs / "2026-11-13.log").write_text(
            "[2026-11-13 17:05:02 UTC] [172.30.0.2:1234] [UDP] "
            + kind + ": " + message + "\n   at " + frame + "\n"
        )

    def test_packet_is_deterministic_pointer_loop(self):
        packet = negative.control_packet()
        self.assertEqual(packet[12:14], bytes.fromhex("c00c"))
        self.assertEqual(struct.unpack_from("!H", packet, 4)[0], 1)

    def test_send_requires_matching_formerr_reply(self):
        packet = negative.control_packet()
        txid = struct.unpack_from("!H", packet)[0]
        response = struct.pack("!HHHHHH", txid, 0x8001, 1, 0, 0, 0)

        class Socket:
            def __init__(self):
                self.sent = None

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def settimeout(self, timeout):
                self.timeout = timeout

            def sendto(self, data, endpoint):
                self.sent = (data, endpoint)

            def recvfrom(self, limit):
                return response, ("127.0.0.1", 53)

        fake = Socket()
        with mock.patch.object(negative.socket, "socket", return_value=fake):
            report = negative.send("127.0.0.1", 53, 1)
        self.assertEqual(report["response_rcode"], 1)
        self.assertEqual(fake.sent[0], packet)

    def test_send_rejects_wrong_response(self):
        packet = negative.control_packet()
        txid = struct.unpack_from("!H", packet)[0]

        class Socket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def settimeout(self, *_):
                pass

            def sendto(self, *_):
                pass

            def recvfrom(self, *_):
                return struct.pack("!HHHHHH", txid, 0x8000, 1, 0, 0, 0), None

        with mock.patch.object(negative.socket, "socket", return_value=Socket()):
            with self.assertRaisesRegex(ValueError, "response invalid"):
                negative.send("127.0.0.1", 53, 1)

    def test_control_detects_live_log_but_normal_allowlist_permits_it(self):
        self.write_log()
        report = negative.evaluate(self.logs, self.baseline, self.rules)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["strict_status"], "failed")
        self.assertEqual(report["strict_unexpected_exceptions"], 1)
        self.assertEqual(report["production_status"], "passed")
        self.assertEqual(report["logged_matches"], 1)

    def test_missing_log_entry_fails_control(self):
        (self.logs / "2026-11-13.log").write_text(
            "[2026-11-13 17:05:02 UTC] No errors\n"
        )
        self.assertEqual(
            negative.evaluate(self.logs, self.baseline, self.rules)["status"], "failed"
        )

    def test_wrong_frame_fails_control(self):
        self.write_log(frame="DnsServerCore.Dns.DnsServer.ProcessRequestAsync()")
        report = negative.evaluate(self.logs, self.baseline, self.rules)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["production_status"], "failed")

    def test_unexpected_exception_fails_production_oracle(self):
        self.write_log(kind="System.IndexOutOfRangeException")
        report = negative.evaluate(self.logs, self.baseline, self.rules)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["production_unexpected_exceptions"], 1)

    def test_sender_errors_create_json(self):
        out = self.root / "out.json"
        with mock.patch.object(negative, "send", side_effect=socket.timeout("no response")):
            rc = negative.main(["send", "--host", "127.0.0.1",
                                "--output", str(out)])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out.read_text())["status"], "error")

    def test_copier_failure_fails_closed(self):
        process = mock.Mock(returncode=1, stderr="no container")
        with mock.patch.object(negative.subprocess, "run", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "docker cp failed"):
                negative.copy_and_verify("tdns", self.baseline, self.rules, 1)


if __name__ == "__main__":
    unittest.main()
