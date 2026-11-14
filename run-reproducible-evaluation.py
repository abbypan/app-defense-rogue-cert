#!/usr/bin/env python3
"""Run a fresh complete public-Internet session with source/runtime evidence.

Launch in an independent background service. The Pixel must already have the
audited ASPin image; this runner never flashes, unlocks, or wipes. DNS is
unchanged unless --dns-server explicitly requests the experiment override.
Existing valid certificate fixtures may be reused, never old measurements.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--device', default='3A201FDJH000GP')
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--cross-deployment', type=Path, required=True)
    parser.add_argument('--certificate-fixtures', type=Path, required=True)
    parser.add_argument('--aosp-root', type=Path, default=Path('/mnt/code/aosp-main/aosp'))
    parser.add_argument('--build-out', type=Path, default=Path('/mnt/code/aosp-main/out/gsi-pixel8-arm64'))
    parser.add_argument('--iterations', type=int, default=20)
    parser.add_argument('--dns-server', choices=('8.8.8.8',),
                        help='Explicit per-network DNS override, reapplied after test reboots')
    args = parser.parse_args()
    directory = args.run_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / 'reproduction.json').exists() or (directory / 'internet').exists():
        parser.error('Use a new session, not an existing experiment')
    if args.iterations < 1:
        parser.error('Positive iteration count required')
    environment = os.environ | {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk',
        'ASPIN_JAVA_HOME': '/usr/lib/jvm/java-21-openjdk', 'PYTHONUNBUFFERED': '1'}
    if args.dns_server:
        environment['ASPIN_BENCHMARK_DNS'] = args.dns_server
    manifest = {'state': 'running', 'created_utc': datetime.now(timezone.utc).isoformat(),
        'historical_measurements_reused': False, 'stages': [], 'workers': 24,
        'dns_server_override': args.dns_server,
        'git_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'python_version': sys.version.split()[0],
        'python_packages': {name: importlib.metadata.version(name) for name in ('cryptography', 'jwcrypto')},
        'certificate_fixture_origin': str(args.certificate_fixtures.resolve().relative_to(ROOT))}

    def save():
        (directory / 'reproduction.json').write_text(json.dumps(manifest, indent=2) + '\n')

    def command(values, timeout=120):
        result = subprocess.run(list(map(str, values)), cwd=ROOT, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stdout[-3000:])
        return result.stdout.strip()

    def adb(*values, timeout=120):
        return command(['adb', '-s', args.device, *values], timeout)

    def stage(name, values):
        item = {'name': name, 'state': 'running', 'started_utc': datetime.now(timezone.utc).isoformat()}
        manifest['stages'].append(item)
        save()
        print('Starting ' + name, flush=True)
        with (directory / (name + '.log')).open('w') as log:
            result = subprocess.run(list(map(str, values)), cwd=ROOT, env=environment,
                stdout=log, stderr=subprocess.STDOUT)
        item.update(state='complete' if result.returncode == 0 else 'failed',
            returncode=result.returncode, finished_utc=datetime.now(timezone.utc).isoformat())
        save()
        if result.returncode:
            raise RuntimeError(name + ' failed; retained log and partial observations')

    save()
    try:
        fixture_module = load('prepare-certificate-change.py')
        fixture_records = fixture_module.inspect_fixtures(args.certificate_fixtures)
        manifest['certificate_fixtures_preflight'] = fixture_records
        save()
        print('Waiting for an authorized ASPin Pixel 8', flush=True)
        deadline = time.monotonic() + 900
        while True:
            status = subprocess.run(['adb', '-s', args.device, 'get-state'],
                capture_output=True, text=True, timeout=10)
            if status.returncode == 0 and status.stdout.strip() == 'device':
                if adb('shell', 'getprop', 'sys.boot_completed') == '1':
                    break
            if time.monotonic() >= deadline:
                raise TimeoutError('No authorized, booted device; no tests were run')
            time.sleep(5)
        if ('Service aspin: found' not in adb('shell', 'service', 'check', 'aspin')
                or adb('shell', 'getprop', 'ro.build.user') != 'exp'
                or adb('shell', 'getprop', 'ro.product.vendor.device') != 'shiba'):
            raise RuntimeError('An ASPin exp Pixel 8 is required, not stock Android')
        adb('root')
        command(['adb', '-s', args.device, 'wait-for-device'], timeout=90)
        if args.dns_server:
            stage('configure-dns', [sys.executable, ROOT / 'benchmark_device_dns.py',
                '--device', args.device, '--dns-server', args.dns_server])
        record = json.loads((ROOT / 'aosp-aspin/experiment-code.json').read_text())
        image = args.build_out / record['image']['path']
        if sha(image) != record['image']['sha256']:
            raise ValueError('Local image differs from audited ASPin runtime')
        stage('aosp-runtime-audit', [sys.executable, ROOT / 'aosp-aspin/check-experiment-code.py',
            '--aosp-root', args.aosp_root, '--build-out', args.build_out])
        runtime = {'image_sha256': sha(image), 'image_bytes': image.stat().st_size,
            'build_properties': {key: adb('shell', 'getprop', key) for key in (
                'ro.build.fingerprint', 'ro.build.user', 'ro.build.date.utc',
                'ro.build.version.incremental', 'ro.boot.slot_suffix')}, 'components': {}}
        for name, expected in record['image']['files_sha256'].items():
            path = '/' + name
            actual = adb('shell', 'sha256sum', path).split()[0]
            if actual != expected:
                raise ValueError('Installed ASPin component differs: ' + path)
            runtime['components'][path] = actual
        slot = runtime['build_properties']['ro.boot.slot_suffix']
        if slot not in ('_a', '_b'):
            raise ValueError('Unexpected dynamic system slot')
        partition = '/dev/block/mapper/system' + slot
        digest_command = ('head -c ' + str(image.stat().st_size) + ' ' + shlex.quote(partition)
                          + ' | sha256sum')
        actual = adb('shell', digest_command, timeout=180).split()[0]
        runtime['system_partition'] = partition
        runtime['installed_image_prefix_sha256'] = actual
        if actual != record['image']['sha256']:
            raise ValueError('Installed raw system image prefix differs from the flashed image')
        manifest['runtime'] = runtime
        runtime_source = directory / 'runtime-source'
        for project in record['projects']:
            if command(['git', '-C', args.aosp_root / project['path'], 'branch', '--show-current']) != 'aspin':
                raise ValueError('AOSP project is not on aspin: ' + project['path'])
            for name, expected in project['source_sha256'].items():
                source = args.aosp_root / project['path'] / name
                if sha(source) != expected:
                    raise ValueError('AOSP source drift: ' + name)
                target = runtime_source / project['path'] / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        bundle = directory / 'aosp-aspin'
        bundle.mkdir()
        for name in ('base.xml', 'patches.tar.zst', 'apply.sh', 'experiment-code.json', 'check-experiment-code.py'):
            shutil.copyfile(ROOT / 'aosp-aspin' / name, bundle / name)
        manifest['runtime_source_sha256'] = {p.relative_to(directory).as_posix(): sha(p)
            for parent in (runtime_source, bundle) for p in parent.rglob('*') if p.is_file()}
        save()
        internet = directory / 'internet'
        stage('internet', [sys.executable, ROOT / 'run-internet-evaluation.py', '--device', args.device,
            '--run-dir', internet, '--deployment', args.deployment,
            '--cross-deployment', args.cross_deployment, '--iterations', args.iterations])
        stage('api-robustness', [sys.executable, ROOT / 'run-remote-api-robustness.py', '--device', args.device,
            '--deployment', args.deployment, '--apk-dir', internet / 'apks',
            '--run-dir', internet / 'api-robustness'])
        stage('audit-internet', [sys.executable, ROOT / 'summarize-internet-evaluation.py', internet,
            '--require-source-snapshot'])
        certificate_change = directory / 'certificate-change'
        certificates = certificate_change / 'certificates'
        # Recheck validity after the preceding suites; no observations are
        # copied from the directory which supplied these certificate inputs.
        fixture_records = fixture_module.inspect_fixtures(args.certificate_fixtures)
        for phase in fixture_module.PHASES:
            target = certificates / phase
            target.mkdir(parents=True)
            for name in ('leaf.pem', 'chain.pem', 'fullchain.pem', 'tls-key.pem', 'server.csr.pem'):
                shutil.copyfile(args.certificate_fixtures / phase / name, target / name)
            (target / 'tls-key.pem').chmod(0o600)
        fixture_module.write_scp_resources(certificates)
        manifest['certificate_fixture_sha256'] = fixture_records
        save()
        stage('build-certificate-change', [sys.executable, ROOT / 'gen-signed-apks.py', '--variant', 'es256',
            '--workers', '24', '--mode', 'primary', '--mode', 'scp', '--mode', 'dcp', '--mode', 'compatible',
            '--scp-resource-dir', certificate_change / 'scp-res', '--output-dir', certificate_change / 'apks'])
        stage('certificate-change', [sys.executable, ROOT / 'run-certificate-change-benchmark.py',
            '--device', args.device, '--deployment', args.deployment, '--run-dir', certificate_change,
            '--iterations', args.iterations, '--warmups', '3'])
        stage('audit-certificate-change', [sys.executable, ROOT / 'summarize-certificate-change-results.py',
            certificate_change])
        load('run-internet-evaluation.py').check_sources_unchanged(ROOT,
            json.loads((internet / 'cohort.json').read_text())['source_sha256'])
        manifest['state'] = 'complete'
    except BaseException as error:
        manifest.update(state='failed', error=str(error))
        raise
    finally:
        manifest['finished_utc'] = datetime.now(timezone.utc).isoformat()
        save()


if __name__ == '__main__':
    main()
