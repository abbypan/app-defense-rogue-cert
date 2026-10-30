"""Offline provenance checks; no device or server is contacted."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("internet_summary", ROOT / "summarize-internet-evaluation.py")
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)
api_spec = importlib.util.spec_from_file_location("internet_api", ROOT / "run-remote-api-robustness.py")
api = importlib.util.module_from_spec(api_spec)
api_spec.loader.exec_module(api)


class InternetEvidenceTest(unittest.TestCase):
    def test_full_cached_dimensions_and_distinct_caller_signers(self):
        self.assertEqual(len(summary.expected_cached_dimensions(["es256"])), 20)
        dimensions = summary.expected_cached_dimensions(summary.ALGORITHMS)
        self.assertEqual(len(dimensions), 32)
        for algorithm in summary.ALGORITHMS:
            self.assertNotEqual(api.caller_signing_variant(algorithm), algorithm)
            self.assertIn(("compat", algorithm, "cross", 8), dimensions)
        for invalid in ([], ["es256", "es256"], ["unknown"]):
            with self.assertRaises(ValueError):
                summary.expected_cached_dimensions(invalid)

    def test_cached_context_cannot_relabel_an_es256_query_as_another_profile(self):
        row = {"API": "cross", "Hostname": "es256.idouzi.top", "TargetAppId": "com.cert.aspin",
               "Operations": "2000", "Successes": "2000", "Failures": "0", "Threads": "8",
               "Mean_ms": "2", "P50_ms": "1", "P95_ms": "3", "P99_ms": "4", "Throughput_ops_s": "1000"}
        case = {"caller": "com.cert.aspin.caller", "algorithm": "es256"}
        summary.validate_cached_context(row, case, 2000)
        with self.assertRaises(ValueError):
            summary.validate_cached_context(row, case | {"algorithm": "rsa3072"}, 2000)
        with self.assertRaises(ValueError):
            summary.validate_cached_context(row | {"API": "self"}, case, 2000)
        with self.assertRaises(ValueError):
            summary.validate_cached_context(row | {"Failures": "1"}, case, 2000)

    def test_api_table_keeps_query_types_and_missing_profiles_separate(self):
        rows = [
            {"Mode": "primary", "Algorithm": "es256", "API": "self", "Threads": "8",
             "P99_ms": "37.610", "Throughput_ops_s": "600.36"},
            {"Mode": "primary", "Algorithm": "es256", "API": "cross", "Threads": "8",
             "P99_ms": "43.565", "Throughput_ops_s": "567.67"},
            {"Mode": "compat", "Algorithm": "es256", "API": "cross", "Threads": "8",
             "P99_ms": "9.628", "Throughput_ops_s": "2419.67"},
        ]
        lines = summary.cached_api_table_lines(rows, (("es256", "ES256"), ("es384", "ES384")))
        self.assertEqual(lines, [
            r"ES256 & Self-query & 37.61 & 600 & -- & --\\",
            r"ES256 & Cross-app query & 43.56 & 568 & 9.63 & 2,420\\",
            r"ES384 & Self-query & -- & -- & -- & --\\",
            r"ES384 & Cross-app query & -- & -- & -- & --\\",
        ])

    def test_api_table_rejects_duplicate_batches(self):
        row = {"Mode": "primary", "Algorithm": "es256", "API": "self", "Threads": "8",
               "P99_ms": "37.610", "Throughput_ops_s": "600.36"}
        with self.assertRaises(ValueError):
            summary.cached_api_table_lines([row, dict(row)], (("es256", "ES256"),))

    def test_adb_probe_omits_empty_extras(self):
        normal = api.probe_extras("new-prime", True, True, "")
        self.assertNotIn("", normal)
        self.assertNotIn("expected_error", normal)
        replay = api.probe_extras("new-replay", False, True, "anti-rollback")
        self.assertEqual(replay[-3:], ["--es", "expected_error", "anti-rollback"])

    def test_only_fresh_complete_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            start = datetime(2026, 10, 29, tzinfo=timezone.utc)
            for state, created in (("running", "2026-10-29T01:00:00+00:00"),
                                   ("failed", "2026-10-29T01:00:00+00:00"),
                                   ("complete", "2026-10-28T23:59:59+00:00")):
                path.write_text(json.dumps({"state": state, "created_utc": created}))
                with self.subTest(state=state, created=created), self.assertRaises(ValueError):
                    summary.fresh_complete(path, start)
            path.write_text(json.dumps({"state": "complete", "created_utc": "2026-10-29T01:00:00+00:00"}))
            self.assertEqual(summary.fresh_complete(path, start)["state"], "complete")


if __name__ == "__main__": unittest.main()
