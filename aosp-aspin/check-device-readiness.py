#!/usr/bin/env python3
"""Check a test reboot and Internet recovery without collecting benchmark samples."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from benchmark_device_network import wait_for_internet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', default='3A201FDJH000GP')
    parser.add_argument('--reboot', action='store_true')
    args = parser.parse_args()

    def adb(*values, check=True):
        result = subprocess.run(['adb', '-s', args.device, *values], capture_output=True,
                                text=True, timeout=180 if values == ('wait-for-device',) else 30)
        if check and result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    power = adb('shell', 'settings', 'get', 'global', 'stay_on_while_plugged_in').strip()
    try:
        if args.reboot:
            print('Rebooting the ASPin test device', flush=True)
            adb('reboot')
            adb('wait-for-device')
            deadline = time.monotonic() + 240
            while adb('shell', 'getprop', 'sys.boot_completed').strip() != '1':
                if time.monotonic() > deadline:
                    raise TimeoutError('Device boot did not complete')
                time.sleep(2)
            adb('root')
            adb('wait-for-device')
        if 'Service aspin: found' not in adb('shell', 'service', 'check', 'aspin'):
            raise RuntimeError('Expected the ASPin-flashed image')
        wait_for_internet(adb, 'es256.idouzi.top')
        print('PASS reboot/readiness: saved Wi-Fi recovered; requested DNS resolves; Internet stable', flush=True)
    finally:
        if power == 'null':
            adb('shell', 'settings', 'delete', 'global', 'stay_on_while_plugged_in', check=False)
        else:
            adb('shell', 'settings', 'put', 'global', 'stay_on_while_plugged_in', power, check=False)


if __name__ == '__main__':
    main()
