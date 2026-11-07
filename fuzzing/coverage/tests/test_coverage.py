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

    def test_snapshot_detects_modified_content_addressed_input(self):
        import hashlib
        import corpus
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seeds = root / "seeds"
            output = root / "snapshot"
            seeds.mkdir()
            output.mkdir()
            (seeds / "case").write_bytes(b"expected")
            digest = hashlib.sha256(b"expected").hexdigest()
            (output / f"{digest}.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "collision"):
                corpus.snapshot(seeds, root / "missing", output)

    def test_snapshot_deterministically_records_queue_provenance(self):
        import corpus
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seeds = root / "seeds"
            queue = root / "queue"
            seeds.mkdir()
            queue.mkdir()
            (seeds / "alpha").write_bytes(b"same")
            (queue / "id:000002").write_bytes(b"other")
            (queue / "id:000001").write_bytes(b"same")
            report = corpus.snapshot(seeds, queue, root / "snapshot")
            self.assertEqual(report["input_count"], 3)
            self.assertEqual(report["duplicates"], 1)
            self.assertEqual([(e["source"], e["name"]) for e in report["entries"]],
                             [("seed", "alpha"), ("queue", "id:000001"),
                              ("queue", "id:000002")])

    def test_snapshot_rejects_oversized_input(self):
        import corpus
        with tempfile.TemporaryDirectory() as directory:
            seeds = Path(directory) / "seeds"
            seeds.mkdir()
            (seeds / "oversized").write_bytes(b"x" * 65536)
            with self.assertRaises(ValueError):
                corpus.snapshot(seeds, Path(directory) / "missing",
                                Path(directory) / "snapshot")


class FindingTriageTests(unittest.TestCase):
    def test_empty_findings_emit_report_not_a_fake_crash(self):
        import triage
        with tempfile.TemporaryDirectory() as directory:
            report = triage.triage(Path(directory) / "missing", Path(directory) / "evidence",
                                   [sys.executable], timeout=2)
            self.assertEqual(report["candidate_count"], 0)
            self.assertEqual(report["confirmed_defects"], 0)
            self.assertEqual(len(report["cases"]), 0)
            self.assertTrue((Path(directory) / "evidence" / "report.json").is_file())

    def test_classifies_success_and_unhandled_exception_without_promotion(self):
        import triage
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crash = root / "default" / "crashes"
            crash.mkdir(parents=True)
            (crash / "id:000001").write_bytes(b"normal")
            (crash / "id:000002").write_bytes(b"failure")
            runner = root / "runner.py"
            runner.write_text(
                "import pathlib,sys\n"
                "data=pathlib.Path(sys.argv[2]).read_bytes()\n"
                "if data==b'failure':\n"
                "  raise RuntimeError('synthetic unhandled failure')\n")
            report = triage.triage(root, root / "evidence",
                                   [sys.executable, str(runner)], timeout=2)
            outcomes = report["outcomes"]
            self.assertEqual(report["candidate_count"], 2)
            self.assertEqual(outcomes["non_reproducible"], 1)
            self.assertEqual(outcomes["abnormal_exit"], 1)
            self.assertEqual(report["confirmed_defects"], 0)
            self.assertEqual(len(list((root / "evidence").glob("*.bin"))), 2)
            self.assertNotIn("confirmed", report["cases"][0]["classification"])

    def test_deduplicates_same_payload_and_groups_provisional_signature(self):
        import triage
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("crashes", "hangs"):
                folder = root / "default" / kind
                folder.mkdir(parents=True)
                (folder / "id:000001").write_bytes(b"same")
            runner = root / "runner.py"
            runner.write_text("import sys\nsys.exit(3)\n")
            report = triage.triage(root, root / "evidence",
                                   [sys.executable, str(runner)], timeout=2)
            self.assertEqual(len(report["cases"]), 2)
            self.assertEqual(len(report["clusters"]), 1)
            self.assertEqual(len(list((root / "evidence").glob("*.bin"))), 1)

    def test_timeout_and_candidate_limit_are_explicit(self):
        import triage
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "default" / "hangs"
            folder.mkdir(parents=True)
            for i in range(2):
                (folder / f"id:{i:06d}").write_bytes(bytes([i]))
            with self.assertRaises(ValueError):
                triage.candidates(root, max_candidates=1)
            runner = root / "runner.py"
            runner.write_text("import time\ntime.sleep(5)\n")
            result = triage.replay(folder / "id:000000",
                                   [sys.executable, str(runner)], timeout=0.05)
            self.assertEqual(result["classification"], "reproduced_timeout")


class ExpandedFuzzingTests(unittest.TestCase):
    def test_target_seed_families_are_repeatable(self):
        import generate_target_seeds
        for target in generate_target_seeds.TARGETS:
            with self.subTest(target=target):
                corpus = generate_target_seeds.target_seeds(target)
                self.assertEqual(corpus, generate_target_seeds.target_seeds(target))
                self.assertGreaterEqual(len(corpus), 7)
                self.assertTrue(all(len(value) <= 65535 for value in corpus.values()))
        self.assertIn("pointer-loop", generate_target_seeds.target_seeds("name"))
        self.assertIn("ds", generate_target_seeds.target_seeds("dnssec"))
        self.assertIn("ecs", generate_target_seeds.target_seeds("edns"))

    def test_grammar_structural_variations_are_bounded(self):
        import generate_structured_seeds
        corpus = generate_structured_seeds.structured_seeds()
        self.assertGreater(len(corpus), 80)
        self.assertLessEqual(len(corpus), 256)
        self.assertEqual(len(corpus), len(set(corpus)))
        self.assertIn("pointer-16383", corpus)
        self.assertIn("qdcount-65535", corpus)
        self.assertIn("rdata-48-length-65535", corpus)
        self.assertIn("edns-8-length-65535", corpus)

    def test_corrupted_artifact_cannot_poison_restored_seeds(self):
        import hashlib
        import io
        import restore_corpus
        import zipfile
        good = b"\x12\x34"
        name = hashlib.sha256(good).hexdigest() + ".bin"
        with io.BytesIO() as archive:
            with zipfile.ZipFile(archive, "w") as zip_file:
                zip_file.writestr(name, good)
                zip_file.writestr("../bad.bin", b"unsafe")
            selected = restore_corpus.choose_samples(archive.getvalue(), 10)
        self.assertEqual(selected, [(name, good)])
        with io.BytesIO() as archive:
            with zipfile.ZipFile(archive, "w") as zip_file:
                zip_file.writestr(name, b"modified")
            with self.assertRaisesRegex(ValueError, "Corrupted"):
                restore_corpus.choose_samples(archive.getvalue(), 10)

    def test_corpus_restore_requires_token(self):
        import restore_corpus
        with tempfile.TemporaryDirectory() as directory:
            result = restore_corpus.restore(
                "zbalkan/TechnitiumLibrary", "fuzz/fixture-integration",
                "fuzz-specialized.yml", "name", Path(directory), token="")
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["imported"], 0)

    def test_campaign_metrics_parse_percentages_and_edge_growth(self):
        import campaign_metrics
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "default"
            root.mkdir()
            (root / "fuzzer_stats").write_text(
                "execs_done : 4500\nexecs_per_sec : 25.5\n"
                "bitmap_cvg : 1.26%\nstability : 99.8%\n"
                "saved_crashes : 0\nsaved_hangs : 0\n")
            (root / "plot_data").write_text(
                "# unix_time, total_edges\n10, 200\n20, 220\n")
            report = campaign_metrics.summarize(Path(directory), "name", 3)
            self.assertEqual(report["executions"], 4500)
            self.assertEqual(report["bitmap_coverage_percent"], 1.26)
            self.assertEqual(report["stability_percent"], 99.8)
            self.assertEqual(report["coverage_series"]["edge_growth"], 20)

    def test_specialized_modes_are_exposed(self):
        program = (ROOT / "DnsParserFuzz" / "Program.cs").read_text()
        specialized = (ROOT / "DnsParserFuzz" / "SpecializedTargets.cs").read_text()
        self.assertIn('"--target"', program)
        self.assertIn('"--replay-target"', program)
        for target in ("name", "rdata", "dnssec", "edns", "serialization"):
            self.assertIn(f'"{target}"', specialized)


class ResourceBudgetSourceTests(unittest.TestCase):
    def test_both_fuzzing_paths_are_capped_during_input_read(self):
        program = (ROOT / "DnsParserFuzz" / "Program.cs").read_text()
        specialized = (ROOT / "DnsParserFuzz" / "SpecializedTargets.cs").read_text()
        cap = (ROOT / "DnsParserFuzz" / "InputBudget.cs").read_text()
        self.assertIn("InputBudget.ReadCapped(input)", program)
        self.assertIn("InputBudget.ReadCapped(input)", specialized)
        self.assertNotIn("input.CopyTo(buffer)", program)
        self.assertNotIn("input.CopyTo(bytes)", specialized)
        self.assertIn("collected.Length + length > MaxBytes", cap)
        self.assertIn("--test-resource-bounds", program)
