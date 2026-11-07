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

class MinimizationTests(unittest.TestCase):
    def test_greedy_cover_preserves_edges(self):
        import minimize
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / f"sample-{n}" for n in range(3)]
            for n, path in enumerate(paths):
                path.write_bytes(bytes([n+1]))
            edges = {paths[0]: frozenset((1, 2)),
                     paths[1]: frozenset((2, 3)),
                     paths[2]: frozenset((1, 2, 3))}
            result = minimize.minimize(paths, Path(directory) / "out",
                                       lambda path, limit: edges[path], 5)
            self.assertEqual(result["selected_count"], 1)
            self.assertEqual(result["measured_edges"], 3)
            self.assertEqual(result["status"], "complete")

    def test_budget_retains_partial_result(self):
        import minimize
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("one", "two")]
            for path in paths:
                path.write_bytes(b"x")
            ticks = iter((0, 0, 2, 2, 2))
            with mock.patch.object(minimize.time, "monotonic", side_effect=lambda: next(ticks)):
                result = minimize.minimize(paths, Path(directory) / "out",
                                           lambda path, limit: frozenset((7,)), 1)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["remaining_count"], 1)
            self.assertEqual(len(list((Path(directory) / "out").glob("*.bin"))), 1)

    def test_edge_map_validation(self):
        import minimize
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "map"
            file.write_text("000001:1\n000008:3\n")
            self.assertEqual(minimize.read_coverage(file), frozenset((1, 8)))
            file.write_text("invalid")
            with self.assertRaises(ValueError):
                minimize.read_coverage(file)

    def test_queue_sampling_is_bounded(self):
        import minimize
        with tempfile.TemporaryDirectory() as directory:
            seeds = Path(directory) / "seeds"
            queue = Path(directory) / "queue"
            seeds.mkdir()
            queue.mkdir()
            for i in range(4):
                (seeds / f"seed-{i}").write_bytes(b"x")
            for i in range(100):
                (queue / f"id:{i:06d}").write_bytes(b"x")
            selected = minimize.candidates(seeds, queue, 10)
            self.assertEqual(len(selected), 14)
            self.assertEqual(sum(path.parent == seeds for path in selected), 4)
