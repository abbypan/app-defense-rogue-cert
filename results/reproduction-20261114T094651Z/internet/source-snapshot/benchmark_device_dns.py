"""Explicit DNS override for the experiment phone, without changing IP or TLS.

Only runs when requested. Android's resolver configuration is per network, so
the benchmark preflight reapplies it after a reboot/reconnection. No Wi-Fi
credentials, firewall rules, certificate stores, or private DNS settings change.
The parcel layout is checked against this image's IDnsResolver version 17.
"""
import argparse
import re
import shlex
import subprocess


def resolver_command(net_id, server='8.8.8.8', opportunistic=True):
    if not isinstance(net_id, int) or net_id < 1 or server != '8.8.8.8':
        raise ValueError('A positive network ID and the requested 8.8.8.8 are required')
    arguments, size = [], 4

    def integer(value):
        nonlocal size
        arguments.extend(('i32', str(value)))
        size += 4

    def string(value):
        nonlocal size
        arguments.extend(('s16', value))
        size += 4 + (len(value.encode('utf-16le')) + 2 + 3) // 4 * 4

    def strings(values):
        integer(len(values))
        for value in values:
            string(value)

    # ResolverParamsParcel in the audited Android 17 image. Keep its normal
    # sample/retry settings and opportunistic private DNS mode unchanged.
    for value in (net_id, 1800, 25, 8, 64, 5000, 2):
        integer(value)
    strings([server])
    strings([])                    # No search domains on this Wi-Fi network.
    string('')                     # No strict-mode TLS hostname.
    strings([server] if opportunistic else [])
    strings([])                    # Deprecated TLS fingerprints.
    string('')                     # No test CA or trust-store modification.
    integer(0)                     # Default TLS connection timeout.
    integer(0)                     # Null resolver options.
    integer(1)                    # One transport.
    integer(1)                    # Wi-Fi.
    integer(0)                     # Unmetered, as before the override.
    integer(0)                     # No explicit DNS-over-HTTPS configuration.
    strings(['wlan0'])
    return ['service', 'call', 'dnsresolver', '3', 'i32', '1',
            'i32', str(size), *arguments]


def network_section(output, net_id):
    for section in re.split(r'(?=^NetId: )', output, flags=re.MULTILINE):
        if section.startswith('NetId: ' + str(net_id) + '\n'):
            return section
    raise RuntimeError('Active network has no resolver configuration')


def configured_servers(section):
    match = re.search(r'  DNS servers:(.*?)\n  Interface names:', section, re.DOTALL)
    if not match:
        raise RuntimeError('Cannot inspect active DNS server list')
    return re.findall(r'^    (\S+) (?:\(|<no data>)', match.group(1), re.MULTILINE)


def configure(adb, server='8.8.8.8'):
    if server != '8.8.8.8':
        raise ValueError('Only the explicitly requested 8.8.8.8 override is supported')
    active = re.search(r'Active default network: (\d+)', adb('shell', 'dumpsys', 'connectivity'))
    if not active:
        return False
    net_id = int(active.group(1))
    section = network_section(adb('shell', 'dumpsys', 'dnsresolver'), net_id)
    if 'TransportType: WIFI' not in section or 'Interface names: [wlan0]' not in section:
        raise RuntimeError('DNS override is restricted to the experiment Wi-Fi')
    mode = re.search(r'Private DNS mode: (\w+)', section)
    if not mode or mode.group(1) not in ('OFF', 'OPPORTUNISTIC'):
        raise RuntimeError('Refusing to replace a strict private-DNS configuration')
    if configured_servers(section) == [server]:
        return False
    if adb('shell', 'id', '-u').strip() != '0':
        raise RuntimeError('Explicit experiment DNS override requires userdebug adb root')
    version = adb('shell', 'service', 'call', 'dnsresolver', '16777215')
    if not re.search(r'00000000\s+00000011\b', version):
        raise RuntimeError('Unsupported resolver interface version; no DNS configuration changed')
    reply = adb('shell', shlex.join(resolver_command(net_id, server, mode.group(1) == 'OPPORTUNISTIC')))
    if not re.search(r'Parcel\(\s*00000000\b', reply):
        raise RuntimeError('Android rejected the experiment DNS configuration: ' + reply)
    after = network_section(adb('shell', 'dumpsys', 'dnsresolver'), net_id)
    if configured_servers(after) != [server]:
        raise RuntimeError('Requested DNS server was not installed')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', default='3A201FDJH000GP')
    parser.add_argument('--dns-server', choices=('8.8.8.8',), required=True)
    args = parser.parse_args()

    def adb(*values):
        return subprocess.check_output(['adb', '-s', args.device, *values], text=True, timeout=20)

    changed = configure(adb, args.dns_server)
    print('DNS configured to 8.8.8.8' if changed else 'DNS already uses 8.8.8.8, or no active network')


if __name__ == '__main__':
    main()
