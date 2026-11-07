"""Independent parser differential comparison tests."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import differential
import generate_seeds


class DifferentialTests(unittest.TestCase):
    def test_valid_and_truncated_dns_datagram(self):
        valid = differential.independent(generate_seeds.seeds()["query-a"])
        invalid = differential.independent(generate_seeds.seeds()["short-header"])
        self.assertTrue(valid["accepted"])
        self.assertEqual(valid["id"], 0x1234)
        self.assertFalse(invalid["accepted"])

    def test_acceptance_disagreement_not_labeled_as_defect(self):
        difference = differential.discrepancy(
            {"accepted": True, "id": 1, "qr": False, "opcode": 0, "rcode": 0},
            {"accepted": False})
        self.assertEqual(difference, ["acceptance"])

    def test_matching_shared_header_semantics(self):
        left = {"accepted": True, "id": 0x1234, "qr": False, "opcode": 0, "rcode": 0}
        right = {"accepted": True, "id": 0x1234, "qr": False, "opcode": 0, "rcode_low4": 0}
        self.assertEqual(differential.discrepancy(left, right), [])
        right["qr"] = True
        self.assertEqual(differential.discrepancy(left, right), ["qr"])

    def test_clean_inspector_output_is_structured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample"
            sample.write_bytes(b"data")
            inspector = root / "inspect.py"
            inspector.write_text('import json\nprint(json.dumps({"accepted": False}))\n')
            result = differential.library(sample, [sys.executable, str(inspector)])
        self.assertFalse(result["accepted"])

    def test_differential_report_does_not_confirm_discrepancies(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample"
            sample.write_bytes(generate_seeds.seeds()["query-a"])
            with mock.patch.object(differential, "library",
                                   return_value={"accepted": False}):
                report = differential.analyze([sample], ["irrelevant"])
        self.assertEqual(report["counts"]["acceptance_disagreement"], 1)
        self.assertIn("not confirmed bugs", report["interpretation"])
