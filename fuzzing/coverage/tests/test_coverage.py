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

    def test_protocol_families_and_section_shapes(self):
        import struct
        corpus = generate_seeds.seeds()
        families = ("response-ds", "response-dnskey-ed25519", "response-rrsig",
                    "response-nsec", "response-nsec3", "query-edns-ecs",
                    "query-edns-unknown", "response-mixed-sections",
                    "malformed-edns-option-length", "malformed-label-64")
        for name in families:
            with self.subTest(name=name):
                self.assertIn(name, corpus)
                self.assertGreaterEqual(len(corpus[name]), 12)
        self.assertEqual(struct.unpack("!HHHH", corpus["response-mixed-sections"][4:12]),
                         (1, 1, 1, 1))
        self.assertEqual(struct.unpack("!H", corpus["query-two-questions"][4:6])[0], 2)

    def test_all_seed_names_are_unique_and_safe(self):
        import re
        corpus = generate_seeds.seeds()
        self.assertEqual(len(corpus), len(set(corpus)))
        self.assertTrue(all(re.fullmatch(r"[a-z0-9-]+", name) for name in corpus))

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

class CorpusPromotionTests(unittest.TestCase):
    def test_promote_is_content_addressed_and_idempotent(self):
        import hashlib
        import corpus
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample"
            source.write_bytes(b"reviewed packet")
            dest = Path(tmp) / "regressions"
            first = corpus.promote(source, dest)
            second = corpus.promote(source, dest)
            self.assertEqual(first, second)
            self.assertEqual(first.name, hashlib.sha256(b"reviewed packet").hexdigest() + ".bin")
            self.assertEqual(len(list(dest.glob("*.bin"))), 1)

    def test_reject_empty_and_oversized_promotions(self):
        import corpus
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample"
            destination = Path(tmp) / "regressions"
            for content in (b"", b"x" * 65536):
                source.write_bytes(content)
                with self.assertRaises(ValueError):
                    corpus.promote(source, destination)

    def test_verify_rejects_tampered_regression_file(self):
        import corpus
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample"
            source.write_bytes(b"baseline")
            destination = Path(tmp) / "regressions"
            sample = corpus.promote(source, destination)
            self.assertEqual(corpus.verify(destination), 1)
            sample.write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                corpus.verify(destination)

class CorpusSnapshotTests(unittest.TestCase):
    def test_snapshot_preserves_distinct_payloads(self):
        import corpus
        with tempfile.TemporaryDirectory() as directory:
            seeds = Path(directory) / "seeds"
            queue = Path(directory) / "queue"
            out = Path(directory) / "snapshot"
            seeds.mkdir()
            queue.mkdir()
            (seeds / "alpha").write_bytes(b"first")
            (seeds / "beta").write_bytes(b"second")
            (queue / "id:000001").write_bytes(b"first")
            (queue / "id:000002").write_bytes(b"third")
            report = corpus.snapshot(seeds, queue, out)
            self.assertEqual(report["input_count"], 4)
            self.assertEqual(report["distinct_inputs"], 3)
            self.assertEqual(report["duplicates"], 1)
            self.assertFalse(report["coverage_minimized"])
            self.assertEqual(len(list(out.glob("*.bin"))), 3)
            self.assertTrue((out / "manifest.json").exists())

    def test_snapshot_keeps_empty_mutation(self):
        import corpus
        with tempfile.TemporaryDirectory() as directory:
            seeds = Path(directory) / "seeds"
            seeds.mkdir()
            (seeds / "empty").write_bytes(b"")
            report = corpus.snapshot(seeds, Path(directory) / "missing",
                                     Path(directory) / "snapshot")
            self.assertEqual(report["distinct_inputs"], 1)

    def test_snapshot_rejects_oversized_input(self):
        import corpus
        with tempfile.TemporaryDirectory() as directory:
            seeds = Path(directory) / "seeds"
            seeds.mkdir()
            (seeds / "oversized").write_bytes(b"x" * 65536)
            with self.assertRaises(ValueError):
                corpus.snapshot(seeds, Path(directory) / "missing",
                                Path(directory) / "snapshot")
