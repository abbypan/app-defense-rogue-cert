#!/usr/bin/env python3
"""Check the paper's AOSP runtime, patch bundle, and experiment source evidence.

Never builds/flashes an image, changes a source checkout, or edits old results.
--recompile runs isolated javac actions; launch that mode in a background service.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

BUNDLE = Path(__file__).resolve().parent
ROOT = BUNDLE.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def run(arguments, **kwargs):
    return subprocess.run(list(map(str, arguments)), check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def class_digest(entries):
    """Bind both class names and bytes, independent of ZIP order/timestamps."""
    result = hashlib.sha256()
    for name, content in sorted(entries.items()):
        result.update(name.encode() + b'\0' + hashlib.sha256(content).digest())
    return result.hexdigest()


def jar_classes(path, prefixes):
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()
                if name.endswith('.class') and any(name.startswith(p) for p in prefixes)}


def javac_arguments(command, aosp, destination):
    """Extract javac only. Never execute the Ninja action's shell or cleanup."""
    words = shlex.split(command)
    start = next((i for i, word in enumerate(words) if word.endswith('/bin/javac')), None)
    require(start is not None, 'No javac action found')
    end = next((i for i in range(start, len(words)) if words[i] in ('&&', ';')),
               len(words))
    arguments = words[start:end]
    # These lists are removed after successful original builds. They are not
    # recreated in the build tree. Missing real source response files are fatal.
    for word in arguments:
        if word.startswith('@') and word.endswith('.rsp'):
            require(Path(word[1:]).is_file(), 'Missing source response file: ' + word[1:])
    arguments = [word for word in arguments
                 if not word.startswith('-J-XX:OnError=')
                 and (not word.startswith('@') or Path(word[1:]).is_file())]
    arguments[0] = str(aosp / arguments[0])
    for flag, directory in (('-d', 'classes'), ('-s', 'generated')):
        require(flag in arguments, 'Missing compiler output flag ' + flag)
        output = destination / directory
        output.mkdir(parents=True)
        arguments[arguments.index(flag) + 1] = str(output)
    return arguments


def read_bundle():
    raw = run(['zstd', '-q', '-d', '-c', BUNDLE / 'patches.tar.zst'])
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        contents = {}
        for member in archive.getmembers():
            if member.isdir():
                require(member.name.rstrip('/') == 'patches', 'Unexpected archive directory')
                continue
            require(member.isfile() and re.fullmatch(r'patches/[A-Za-z0-9._-]+', member.name),
                    'Unsafe archive member')
            name = member.name.split('/')[1]
            require(name not in contents, 'Duplicate archive member')
            contents[name] = archive.extractfile(member).read()
    covered = set()
    for line in contents['SHA256SUMS'].decode().splitlines():
        digest, name = line.split('  ', 1)
        require(name in contents and sha256(contents[name]) == digest,
                'Archive checksum mismatch: ' + name)
        covered.add(name)
    require(covered == set(contents) - {'SHA256SUMS'}, 'Incomplete archive checksums')
    series = [line.split('|') for line in contents['series'].decode().splitlines()
              if line and not line.startswith('#')]
    return contents, series


def check_sources(aosp, record):
    contents, series = read_bundle()
    manifest = {item.get('path'): item for item in
                ET.parse(BUNDLE / 'base.xml').getroot().findall('project')}
    require(file_sha256(BUNDLE / 'patches.tar.zst') == record['bundle_sha256'],
            'Patch archive differs from the audited experimental runtime')
    require(file_sha256(BUNDLE / 'base.xml') == record['base_manifest_sha256'],
            'Baseline manifest differs from the audit')
    require(series == [[p['path'], p['baseline'], p['patch']] for p in record['projects']],
            'Patch series differs from the audit')
    for project in record['projects']:
        path = aosp / project['path']
        git = ['git', '-C', path]
        require(manifest[project['path']].get('revision') == project['baseline'],
                'Unpinned baseline: ' + project['path'])
        require(not run(git + ['status', '--porcelain', '--untracked-files=all']),
                'Dirty AOSP project: ' + project['path'])
        require(run(git + ['rev-parse', 'HEAD^{tree}']).decode().strip() == project['tree'],
                'AOSP tree differs from the experimental source: ' + project['path'])
        with tempfile.TemporaryDirectory(prefix='aspin-audit-index-') as directory:
            environment = os.environ | {'GIT_INDEX_FILE': str(Path(directory) / 'index')}
            run(git + ['read-tree', project['baseline']], env=environment)
            run(git + ['apply', '--cached', '--binary', '--whitespace=error-all', '-'],
                input=contents[project['patch']], env=environment)
            tree = run(git + ['write-tree'], env=environment).decode().strip()
        require(tree == project['tree'], 'Patched tree mismatch: ' + project['path'])
        changed = run(git + ['diff', '--name-only', project['baseline'], 'HEAD']).decode().splitlines()
        require(set(changed) == set(project['source_sha256']), 'Changed-file inventory mismatch')
        for name, digest in project['source_sha256'].items():
            require(file_sha256(path / name) == digest, 'Source mismatch: ' + name)
        print('PASS patch/source tree: ' + project['path'], flush=True)
    for item in record['experiment_references']:
        require(file_sha256(ROOT / item['manifest']) == item['sha256'],
                'Experimental reference changed: ' + item['manifest'])
        manifest = json.loads((ROOT / item['manifest']).read_text())
        if 'recorded_source_field' in item:
            recorded = manifest[item['recorded_source_field']]
            resolutions = item['source_resolutions']
            require({entry['path']: entry['sha256'] for entry in resolutions} == recorded,
                    'Historical-source inventory differs from its experiment manifest')
            for entry in resolutions:
                if entry.get('snapshot'):
                    require(entry['status'] == 'source_archived', 'Invalid source snapshot status')
                    relative = Path(entry['snapshot'])
                    require(not relative.is_absolute() and '..' not in relative.parts,
                            'Unsafe source snapshot path')
                    source = ROOT / relative
                    require(not any(p.is_symlink() for p in (source, *source.parents) if p != ROOT),
                            'Source snapshot contains a symlink')
                    require(file_sha256(source) == entry['sha256'],
                            'Archived source mismatch: ' + entry['path'])
                    continue
                if entry.get('git_revision') is None:
                    require(entry['status'] == 'hash_only_original_driver_not_archived',
                            'Missing historical source must be disclosed')
                    continue
                content = run(['git', '-C', ROOT, 'show',
                               entry['git_revision'] + ':' + entry['path']])
                require(sha256(content) == entry['sha256'],
                        'Historical source mismatch: ' + entry['path'])
    for name, digest in record.get('additional_artifacts_sha256', {}).items():
        require(file_sha256(ROOT / name) == digest, 'Archived artifact mismatch: ' + name)
    if 'measurement_runtime' in record:
        runtime = json.loads((ROOT / record['measurement_runtime']).read_text())
        require(runtime['state'] == 'complete', 'Incomplete measurement-time runtime record')
        observed = runtime['runtime']
        require(observed['image_sha256'] == record['image']['sha256']
                == observed['installed_image_prefix_sha256'], 'Installed image digest differs')
        require(observed['components'] == {'/' + name: digest
                for name, digest in record['image']['files_sha256'].items()},
                'Installed runtime component digest differs')
        if 'active_nsc_jar_sha256' in observed:
            require(observed['active_nsc_jar_sha256'] == record['image']['nsc_payload_jar_sha256'],
                    'Active Conscrypt NSC differs from the preserved image')
    print('PASS experiment-reference hashes and available source bytes', flush=True)


def check_source_coverage(record, require_complete=False):
    """Distinguish AOSP runtime validation from historical-driver completeness."""
    gaps = []
    for item in record['experiment_references']:
        for entry in item.get('source_resolutions', []):
            if entry.get('snapshot'):
                require(entry.get('status') == 'source_archived', 'Invalid source snapshot status')
                continue
            if entry.get('git_revision') is None:
                require(entry['status'] == 'hash_only_original_driver_not_archived',
                        'Missing historical source must be disclosed')
                gaps.append((item['manifest'], entry['path'], entry['sha256']))
    require(not require_complete or not gaps,
            'Historical test-driver source coverage is incomplete: ' +
            str(len(gaps)) + ' recorded source snapshots are unavailable')
    return gaps


def image_file(image, name):
    require(re.fullmatch(r'[A-Za-z0-9/._-]+', name) is not None, 'Unsafe image path')
    return run(['debugfs', '-R', 'cat /' + name, image])


def check_build(out, record):
    for group in record['class_groups']:
        jar = out / group['jar']
        require(file_sha256(jar) == group['jar_sha256'], 'Original class JAR changed: ' + group['name'])
        classes = jar_classes(jar, group['prefixes'])
        require(len(classes) == group['class_count'] and
                class_digest(classes) == group['class_set_sha256'],
                'Original class set changed: ' + group['name'])
    image = out / record['image']['path']
    require(file_sha256(image) == record['image']['sha256'], 'Preserved system image changed')
    for name, digest in record['image']['files_sha256'].items():
        content = image_file(image, name)
        require(sha256(content) == digest and file_sha256(out / 'target/product/generic_arm64' / name) == digest,
                'Image/build-output mismatch: ' + name)
    # Conscrypt NSC is in the EROFS payload inside a compressed APEX, not in
    # /system/framework. Check the actual payload rather than a sibling JAR.
    with zipfile.ZipFile(io.BytesIO(image_file(image, 'system/apex/com.android.conscrypt.capex'))) as capex:
        with zipfile.ZipFile(io.BytesIO(capex.read('original_apex'))) as apex:
            payload = apex.read('apex_payload.img')
    with tempfile.TemporaryDirectory(prefix='aspin-audit-apex-') as directory:
        directory = Path(directory)
        payload_path = directory / 'payload.img'
        payload_path.write_bytes(payload)
        run([out / 'host/linux-x86/bin/fsck.erofs', '--extract=' + str(directory / 'files'), payload_path])
        require(file_sha256(directory / 'files/javalib/framework-conscrypt-nsc.jar') ==
                record['image']['nsc_payload_jar_sha256'], 'Image NSC payload differs')
    for filename, expected_properties in record['image']['measured_build_properties'].items():
        properties = dict(line.split('=', 1) for line in image_file(image, filename).decode().splitlines()
                          if line and not line.startswith('#') and '=' in line)
        for name, expected in expected_properties.items():
            require(properties.get(name) == expected, 'Measured image property differs: ' + name)
    print('PASS preserved image, packaged runtime files, NSC APEX, measured build properties', flush=True)


def recompile(aosp, out, record):
    commands = run([aosp / 'prebuilts/build-tools/linux-x86/bin/ninja', '-f',
                    out / 'combined-gsi_arm64.ninja', '-t', 'commands', '-s',
                    *[out / group['jar'] for group in record['class_groups']]],
                   cwd=aosp, timeout=120).decode().splitlines()
    require(len(commands) == len(record['class_groups']), 'Unexpected compiler-action count')
    with tempfile.TemporaryDirectory(prefix='aspin-audit-javac-') as directory:
        for group, command in zip(record['class_groups'], commands):
            destination = Path(directory) / group['name']
            arguments = javac_arguments(command, aosp, destination)
            try:
                run(arguments, cwd=aosp, timeout=300)
            except subprocess.CalledProcessError as error:
                raise ValueError('Isolated compilation failed for ' + group['name'] + ': ' +
                                 error.stderr.decode(errors='replace')[-1800:]) from error
            original = jar_classes(out / group['jar'], group['prefixes'])
            actual = {name: (destination / 'classes' / name).read_bytes() for name in original}
            require(class_digest(actual) == group['class_set_sha256'],
                    'Recompiled classes differ from the measured-build artifacts: ' + group['name'])
            print('PASS isolated recompile: ' + group['name'] +
                  ' (' + str(len(actual)) + ' byte-identical classes)', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aosp-root', type=Path, default=Path('/mnt/code/aosp-main/aosp'))
    parser.add_argument('--build-out', type=Path)
    parser.add_argument('--recompile', action='store_true')
    parser.add_argument('--require-complete-sources', action='store_true',
                        help='Fail if any historical test driver has only a hash, not its source')
    args = parser.parse_args()
    if args.recompile and args.build_out is None:
        parser.error('--recompile requires --build-out')
    record = json.loads((BUNDLE / 'experiment-code.json').read_text())
    gaps = check_source_coverage(record, args.require_complete_sources)
    check_sources(args.aosp_root.resolve(), record)
    if args.build_out is not None:
        check_build(args.build_out.resolve(), record)
    if args.recompile:
        recompile(args.aosp_root.resolve(), args.build_out.resolve(), record)
    for boundary in record['limitations']:
        print('NOTE: ' + boundary)
    if gaps:
        print('PARTIAL historical test-driver source coverage: ' + str(len(gaps)) +
              ' snapshots unavailable; no claim of complete historical app-build reproduction')
    print('PASS within the recorded AOSP runtime scope; no image build, flash, or new measurement')


if __name__ == '__main__':
    main()
