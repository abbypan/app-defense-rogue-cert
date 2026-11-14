"""Offline regressions for patch/runtime audit integrity and safe compilation."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('experiment_code',
    Path(__file__).parent / 'aosp-aspin/check-experiment-code.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class ExperimentCodeAuditTest(unittest.TestCase):
    def test_incomplete_historical_driver_sources_are_not_complete_reproduction(self):
        record = {'experiment_references': [{'manifest': 'cohort.json', 'source_resolutions': [
            {'path': 'MainActivity.java', 'sha256': 'a' * 64, 'git_revision': None,
             'status': 'hash_only_original_driver_not_archived'}]}]}
        self.assertEqual(audit.check_source_coverage(record),
                         [('cohort.json', 'MainActivity.java', 'a' * 64)])
        with self.assertRaisesRegex(ValueError, 'source coverage is incomplete'):
            audit.check_source_coverage(record, require_complete=True)

    def test_undisclosed_missing_source_is_fatal(self):
        record = {'experiment_references': [{'source_resolutions': [
            {'path': 'MainActivity.java', 'sha256': 'a' * 64, 'git_revision': None,
             'status': 'source_available'}]}]}
        with self.assertRaisesRegex(ValueError, 'must be disclosed'):
            audit.check_source_coverage(record)

    def test_retained_historical_sources_have_no_reported_gap(self):
        record = {'experiment_references': [{'source_resolutions': [
            {'git_revision': 'f' * 40, 'status': 'source_available'}]}]}
        self.assertEqual(audit.check_source_coverage(record, require_complete=True), [])

    def test_class_digest_is_order_independent(self):
        self.assertEqual(audit.class_digest({'A.class': b'a', 'B.class': b'b'}),
                         audit.class_digest({'B.class': b'b', 'A.class': b'a'}))

    def test_names_and_nested_class_bytes_are_bound(self):
        original = {'A.class': b'a', 'A$B.class': b'b'}
        self.assertNotEqual(audit.class_digest(original),
                            audit.class_digest({'A.class': b'a', 'A$B.class': b'changed'}))
        self.assertNotEqual(audit.class_digest(original),
                            audit.class_digest({'A.class': b'a', 'A$C.class': b'b'}))

    def test_shell_cleanup_is_not_executed_and_outputs_are_redirected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = ('rm -rf /old/classes && prebuilts/jdk/bin/javac -g '
                       '-d /old/classes -s /old/generated -J-XX:OnError=unsafe '
                       '@/absent/srcjars/list ; fi ) && touch /should-not-exist')
            arguments = audit.javac_arguments(command, root, root / 'audit')
            self.assertEqual(arguments[0], str(root / 'prebuilts/jdk/bin/javac'))
            self.assertEqual(arguments[arguments.index('-d') + 1], str(root / 'audit/classes'))
            self.assertNotIn('rm', arguments)
            self.assertNotIn('touch', arguments)
            self.assertNotIn('@/absent/srcjars/list', arguments)
            self.assertFalse(any(word.startswith('-J-XX:OnError=') for word in arguments))

    def test_missing_real_source_response_file_is_fatal(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'source response file'):
                audit.javac_arguments('jdk/bin/javac -d x -s y @/absent/source.rsp',
                                      Path(temporary), Path(temporary) / 'output')

    def test_no_compiler_is_fatal(self):
        with self.assertRaisesRegex(ValueError, 'No javac'):
            audit.javac_arguments('touch /bad', Path('/unused'), Path('/unused'))

    def test_zip_order_metadata_and_unrelated_classes_are_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'classes.jar'
            with zipfile.ZipFile(target, 'w') as archive:
                archive.writestr('unrelated/Z.class', b'z')
                archive.writestr('wanted/A$B.class', b'b')
                archive.writestr('wanted/A.class', b'a')
                archive.writestr('wanted/README', b'note')
            self.assertEqual(audit.jar_classes(target, ['wanted/']),
                             {'wanted/A.class': b'a', 'wanted/A$B.class': b'b'})


if __name__ == '__main__':
    unittest.main()
