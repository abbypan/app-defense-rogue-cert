"""Offline checks for the explicitly requested experiment DNS override."""
import shlex
import unittest

import benchmark_device_dns as dns


def section(servers, mode='OPPORTUNISTIC', interface='wlan0'):
    return ('NetId: 100\n  DNS servers: # IP (statistics)\n'
            + ''.join('    ' + server + ' <no data>\n' for server in servers)
            + '\n  Interface names: [' + interface + ']\n'
            + '  Private DNS mode: ' + mode + '\n  TransportType: WIFI\n')


class DnsOverrideTest(unittest.TestCase):
    def test_parcel_size_and_quoted_empty_strings(self):
        command = dns.resolver_command(100)
        self.assertEqual(command[:8], ['service', 'call', 'dnsresolver', '3', 'i32', '1', 'i32', '148'])
        self.assertEqual(shlex.split(shlex.join(command)), command)
        payload = command[8:]
        size = 4
        for kind, value in zip(payload[::2], payload[1::2]):
            size += 4 if kind == 'i32' else 4 + (len(value.encode('utf-16le')) + 5) // 4 * 4
        self.assertEqual(size, int(command[7]))
        self.assertNotIn('192.168.1.1', command)
        self.assertEqual(command.count('8.8.8.8'), 2)
        self.assertEqual(dns.resolver_command(100, opportunistic=False).count('8.8.8.8'), 1)

    def test_server_parser_accepts_unsampled_and_sampled_entries(self):
        self.assertEqual(dns.configured_servers(section(['8.8.8.8'])), ['8.8.8.8'])
        sampled = section(['8.8.8.8']).replace('<no data>', '(1, 1, 0, 0)')
        self.assertEqual(dns.configured_servers(sampled), ['8.8.8.8'])
        self.assertEqual(dns.configured_servers(section(['fe80::1%wlan0', '192.168.1.1'])),
                         ['fe80::1%wlan0', '192.168.1.1'])

    def test_only_supported_server_and_positive_network_are_allowed(self):
        for net_id, server in ((0, '8.8.8.8'), (100, '192.168.1.1'), ('100', '8.8.8.8')):
            with self.assertRaises(ValueError):
                dns.resolver_command(net_id, server)

    def fake_adb(self, mode='OPPORTUNISTIC', version='00000011', interface='wlan0'):
        state = {'servers': ['192.168.1.1'], 'mutations': []}

        def adb(*values):
            if values == ('shell', 'dumpsys', 'connectivity'):
                return 'Active default network: 100\n'
            if values == ('shell', 'dumpsys', 'dnsresolver'):
                return section(state['servers'], mode, interface)
            if values == ('shell', 'id', '-u'):
                return '0\n'
            if values == ('shell', 'service', 'call', 'dnsresolver', '16777215'):
                return 'Result: Parcel(00000000 ' + version + ')'
            if len(values) == 2 and values[0] == 'shell':
                state['mutations'].append(shlex.split(values[1]))
                state['servers'] = ['8.8.8.8']
                return 'Result: Parcel(00000000)'
            raise AssertionError(values)

        return adb, state

    def test_applies_once_then_only_checks_configuration(self):
        adb, state = self.fake_adb()
        self.assertTrue(dns.configure(adb))
        self.assertFalse(dns.configure(adb))
        self.assertEqual(len(state['mutations']), 1)
        self.assertEqual(state['mutations'][0], dns.resolver_command(100))

    def test_never_overrides_strict_private_dns_or_unknown_interface(self):
        for kwargs in ({'mode': 'STRICT'}, {'version': '00000010'}, {'interface': 'rmnet0'}):
            adb, state = self.fake_adb(**kwargs)
            with self.assertRaises(RuntimeError):
                dns.configure(adb)
            self.assertEqual(state['mutations'], [])


if __name__ == '__main__':
    unittest.main()
