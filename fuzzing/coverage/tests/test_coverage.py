"""Behaviour tests for the parser corpus and coverage harness layout."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import generate_seeds

class CorpusTests(unittest.TestCase):
    def test_seed_corpus_has_valid_dns_headers(self):
        seeds = generate_seeds.seeds()
        self.assertGreaterEqual(len(seeds), 10)
        self.assertEqual(seeds["query-a"][:2], b"\x12\x34")
        self.assertEqual(seeds["response-a"][6:8], b"\x00\x01")
        self.assertEqual(seeds["query-edns"][10:12], b"\x00\x01")

    def test_seeds_are_binary_and_bounded(self):
        seeds = generate_seeds.seeds()
        self.assertTrue(all(isinstance(data, bytes) for data in seeds.values()))
        self.assertTrue(all(0 < len(data) <= 65535 for data in seeds.values()))

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "seeds"
            with mock.patch.object(sys, "argv", ["generate_seeds.py", "--output", str(output)]):
                generate_seeds.main()
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()},
                             generate_seeds.seeds())

    def test_harness_uses_sharpfuzz_and_parser(self):
        program = (ROOT / "DnsParserFuzz" / "Program.cs").read_text()
        self.assertIn("Fuzzer.OutOfProcess.Run(Parse)", program)
        self.assertIn("DnsDatagram.ReadFrom(buffer)", program)
        self.assertIn("datagram.ParsingException", program)
        self.assertNotIn("ExceptionDispatchInfo.Capture", program)
        self.assertNotIn("ExpectedStoredParseFailure", program)
        self.assertIn("catch (EndOfStreamException)", program)
        self.assertIn("ParseDatagram(() => throw new InvalidOperationException", program)
        self.assertIn("SemanticOracle.AssertWireHeaderMatches", program)
        self.assertIn("--verify-seeds", program)
        self.assertNotIn("catch (Exception) { }", program)

    def test_semantic_oracle_corpus_expectations_exist(self):
        program = (ROOT / "DnsParserFuzz" / "Program.cs").read_text()
        for name in ("query-a", "response-soa", "response-ede",
                     "short-header", "compression-loop", "rr-truncated"):
            self.assertIn(f'"{name}"', program)
        source = (ROOT / "DnsParserFuzz" / "SemanticOracle.cs").read_text()
        self.assertIn("AssertWireHeaderMatches", source)
        self.assertIn("AssertRoundTrip", source)
