#!/usr/bin/env python3
"""Bind the unchanged AOSP runtime record to one fully audited fresh session.

This updates audit metadata, not source patches or measurement observations.
Run only after every suite is complete, before removing retired result folders.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / 'aosp-aspin'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session', type=Path)
    args = parser.parse_args()
    session = args.session.resolve()
    session.relative_to(ROOT / 'results')
    report_path = session / 'reproduction.json'
    report = json.loads(report_path.read_text())
    if report['state'] != 'complete' or report['historical_measurements_reused']:
        raise ValueError('Only a completed fresh session can replace the published evidence')
    for name in ('internet', 'certificate-change'):
        if json.loads((session / name / 'checks.json').read_text())['result'] != 'PASS':
            raise ValueError('Independent evidence audit did not pass: ' + name)
    record = json.loads((BUNDLE / 'experiment-code.json').read_text())
    if report['runtime']['installed_image_prefix_sha256'] != record['image']['sha256']:
        raise ValueError('The measured device did not use the recorded AOSP image')
    snapshot = session / 'internet/source-snapshot'
    auxiliary = session / 'internet/functional/aux-apks/checks.json'
    verified = json.loads(auxiliary.read_text())
    if verified['result'] != 'PASS' or not verified['installed_packages_match_archived_bytes']:
        raise ValueError('Functional caller APK comparison is missing')
    for name, digest in verified['files_sha256'].items():
        if sha(auxiliary.parent / name) != digest:
            raise ValueError('Archived functional caller APK changed: ' + name)
    references = []
    for name, field in (
            ('internet/cohort.json', 'source_sha256'),
            ('internet/comparison/matrix.json', None),
            ('internet/functional/manifest.json', None),
            ('internet/public-cross/manifest.json', None),
            ('internet/api-robustness/manifest.json', 'app_source_sha256'),
            ('certificate-change/manifest.json', 'source_sha256')):
        path = session / name
        item = {'manifest': path.relative_to(ROOT).as_posix(), 'sha256': sha(path)}
        if field:
            item['recorded_source_field'] = field
            item['source_resolutions'] = []
            for source_name, digest in json.loads(path.read_text())[field].items():
                source = snapshot / source_name
                if not source.is_file() or sha(source) != digest:
                    raise ValueError('Missing exact measurement source: ' + source_name)
                item['source_resolutions'].append({'path': source_name, 'sha256': digest,
                    'status': 'source_archived', 'snapshot': source.relative_to(ROOT).as_posix()})
        references.append(item)
    record.update(schema_version=2, audited_utc=datetime.now(timezone.utc).isoformat(),
        audit_kind='AOSP source/patch/runtime audit linked to a fresh, source-archived Internet session',
        experiment_references=references, measurement_runtime=report_path.relative_to(ROOT).as_posix(),
        scope='Recorded AOSP runtime plus exact archived sources of the fresh experiment drivers',
        limitations=[
            'Source/bytecode/image checks and measurement-time device hashes are not a signed build attestation or a reproducible full-image rebuild.',
            'The experiment retains selected source/build/public-input bytes and APK hashes, not every toolchain dependency byte.',
            'Single-device, fixed-order Internet observations do not establish deployment-scale performance or privileged rollback resistance.'])
    record['additional_artifacts_sha256'] = {
        path.relative_to(ROOT).as_posix(): sha(path)
        for path in [auxiliary, *sorted(session.rglob('*.apk'))]}
    (BUNDLE / 'experiment-code.json').write_text(json.dumps(record, indent=2) + '\n')
    # Preserve the exact pre-run audit inputs. Updated reference metadata and
    # its verifier are separate post-run evidence, never substituted for them.
    post_run = session / 'post-run-audit'
    post_run.mkdir(exist_ok=True)
    report['post_run_audit_sha256'] = {}
    for name in ('experiment-code.json', 'check-experiment-code.py', 'refresh-experiment-evidence.py'):
        target = post_run / name
        shutil.copyfile(BUNDLE / name, target)
        report['post_run_audit_sha256'][target.relative_to(session).as_posix()] = sha(target)
    report['post_run_reference_refresh_utc'] = datetime.now(timezone.utc).isoformat()
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print('Fresh source snapshots and measured runtime are now the sole experiment references')


if __name__ == '__main__':
    main()
