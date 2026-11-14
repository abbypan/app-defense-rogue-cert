"""Offline provenance checks; no device or server is contacted."""
from datetime import datetime, timezone
import hashlib
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
runner_spec = importlib.util.spec_from_file_location('internet_runner', ROOT / 'run-internet-evaluation.py')
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


class InternetEvidenceTest(unittest.TestCase):
    def test_source_snapshot_keeps_exact_bytes_and_excludes_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'project'
            root.mkdir()
            source = root / 'ASPin/es256/app/src/main/java/com/cert/aspin/MainActivity.java'
            source.parent.mkdir(parents=True)
            content = b'public class MainActivity {\r\n}\r\n'
            source.write_bytes(content)
            (root / 'run-remote-example.py').write_bytes(b'print("test")\n')
            (root / 'my-app-key.pem').write_bytes(b'not public source')
            directory = Path(temporary) / 'run'
            directory.mkdir()
            recorded = runner.snapshot_sources(root, directory)
            name = source.relative_to(root).as_posix()
            self.assertEqual(recorded[name], hashlib.sha256(content).hexdigest())
            self.assertEqual((directory / 'source-snapshot' / name).read_bytes(), content)
            self.assertEqual(set(recorded), {name, 'run-remote-example.py'})
            cohort = {'source_snapshot': 'source-snapshot', 'source_sha256': recorded}
            self.assertEqual(len(summary.audit_source_snapshot(directory, cohort, True)), 2)
            runner.check_sources_unchanged(root, recorded)
            source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed after snapshot'):
                runner.check_sources_unchanged(root, recorded)
            self.assertEqual(len(summary.audit_source_snapshot(directory, cohort, True)), 2)
            (directory / 'source-snapshot' / name).write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'Archived experiment source changed'):
                summary.audit_source_snapshot(directory, cohort, True)

    def test_legacy_hashes_are_not_claimed_as_recovered_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cohort = {'source_sha256': {'MainActivity.java': 'a' * 64}}
            self.assertIsNone(summary.audit_source_snapshot(directory, cohort))
            with self.assertRaisesRegex(ValueError, 'hashes alone are not source recovery'):
                summary.audit_source_snapshot(directory, cohort, True)

    def test_snapshot_retains_build_and_public_fixture_inputs_not_private_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'project'
            directory = Path(temporary) / 'run'
            directory.mkdir()
            public = (
                'ASPin/es256/app/build.gradle.kts',
                'ASPin/es256/app/src/main/AndroidManifest.xml',
                'ASPin/es256/app/src/scpBenchmark/res/xml/network_security_config.xml',
                'ASPin/es256/gradle/wrapper/gradle-wrapper.jar',
                'signing/es256/my-app-cert.pem',
                'realserver/etc/cert/es256/real-chain.pem',
            )
            private = ('signing/es256/my-app-key.pem',
                       'signing/es256/my-claim-key.pem',
                       'signing/es256/my-dcp-key.pem',
                       'realserver/etc/cert/es256/real-privkey.pem')
            for name in (*public, *private):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            recorded = runner.snapshot_sources(root, directory)
            self.assertEqual(set(recorded), set(public))
            for name in private:
                self.assertFalse((directory / 'source-snapshot' / name).exists())

    def test_source_snapshot_rejects_missing_or_unlisted_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = directory / 'source-snapshot'
            snapshot.mkdir()
            cohort = {'source_snapshot': 'source-snapshot',
                      'source_sha256': {'MainActivity.java': hashlib.sha256(b'original').hexdigest()}}
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                summary.audit_source_snapshot(directory, cohort)
            (snapshot / 'MainActivity.java').write_bytes(b'original')
            (snapshot / 'unlisted.java').write_bytes(b'extra')
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                summary.audit_source_snapshot(directory, cohort)

    def test_snapshot_refuses_source_symlinks_before_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'project'
            root.mkdir()
            outside = Path(temporary) / 'private.pem'
            outside.write_bytes(b'not public source')
            (root / 'run-remote-example.py').symlink_to(outside)
            directory = Path(temporary) / 'run'
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, 'does not allow symlinks'):
                runner.snapshot_sources(root, directory)
            self.assertFalse((directory / 'source-snapshot').exists())

    def test_snapshot_audit_rejects_symlinks_and_other_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = directory / 'source-snapshot'
            snapshot.mkdir()
            outside = directory / 'outside.java'
            outside.write_bytes(b'original')
            (snapshot / 'MainActivity.java').symlink_to(outside)
            cohort = {'source_snapshot': 'source-snapshot',
                      'source_sha256': {'MainActivity.java': hashlib.sha256(b'original').hexdigest()}}
            with self.assertRaisesRegex(ValueError, 'contains a symlink'):
                summary.audit_source_snapshot(directory, cohort)
            with self.assertRaisesRegex(ValueError, 'Unexpected source snapshot directory'):
                summary.audit_source_snapshot(directory, cohort | {'source_snapshot': '../other'})

    def test_snapshot_never_overwrites_an_existing_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'project'
            root.mkdir()
            (root / 'run-remote-example.py').write_bytes(b'original')
            directory = Path(temporary) / 'run'
            directory.mkdir()
            runner.snapshot_sources(root, directory)
            with self.assertRaises(FileExistsError):
                runner.snapshot_sources(root, directory)
            self.assertEqual((directory / 'source-snapshot/run-remote-example.py').read_bytes(), b'original')

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
