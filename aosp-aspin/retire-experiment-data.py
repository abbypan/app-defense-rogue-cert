#!/usr/bin/env python3
"""Retire old result entries only after the new paper evidence is audited.

Dry-run by default. --delete permanently removes the explicitly listed old
entries beneath this project's results directory, never source or fixtures.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep', type=Path, required=True)
    parser.add_argument('--delete', action='store_true')
    args = parser.parse_args()
    results = (ROOT / 'results').resolve()
    keep = args.keep.resolve()
    if keep.parent != results or not keep.is_dir() or args.keep.is_symlink():
        raise ValueError('Keep exactly one existing immediate result-session directory')
    report = json.loads((keep / 'reproduction.json').read_text())
    checks = json.loads((keep / 'internet/checks.json').read_text())
    certificate = json.loads((keep / 'certificate-change/checks.json').read_text())
    if (report['state'] != 'complete' or report['historical_measurements_reused']
            or checks['result'] != 'PASS' or certificate['result'] != 'PASS'
            or checks.get('paper_tables_match_fresh_evidence') is not True):
        raise ValueError('Complete fresh evidence and a matching updated paper are required')
    record = json.loads((ROOT / 'aosp-aspin/experiment-code.json').read_text())
    if (ROOT / record['measurement_runtime']).resolve() != keep / 'reproduction.json':
        raise ValueError('AOSP experiment references still point to a different session')
    for item in record['experiment_references']:
        (ROOT / item['manifest']).resolve().relative_to(keep)
    subprocess.run(['python3', str(ROOT / 'aosp-aspin/check-experiment-code.py'),
                    '--require-complete-sources'], cwd=ROOT, check=True)
    candidates = []
    for entry in sorted(results.iterdir()):
        if entry == keep:
            continue
        if entry.is_symlink() or entry.resolve().parent != results:
            raise ValueError('Unsafe old-result target: ' + str(entry))
        candidates.append(entry)
    print('\n'.join(str(path) for path in candidates))
    print(str(len(candidates)) + ' old result entries; ' + ('DELETING' if args.delete else 'dry run only'))
    if not args.delete:
        return
    for path in candidates:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    (keep / 'retired-results.json').write_text(json.dumps({
        'removed_utc': datetime.now(timezone.utc).isoformat(),
        'removed_paths': [path.relative_to(ROOT).as_posix() for path in candidates],
        'permanent_working_directory_removal': True,
        'git_history_rewritten': False,
        'kept_session': keep.relative_to(ROOT).as_posix(),
        'fixture_and_source_directories_untouched': True}, indent=2) + '\n')


if __name__ == '__main__':
    main()
