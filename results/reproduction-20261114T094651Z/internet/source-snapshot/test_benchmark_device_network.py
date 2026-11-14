import unittest
from unittest.mock import patch
from benchmark_device_network import sole_saved_ssid, saved_network_center, reconnect_saved_network


class ReadinessTest(unittest.TestCase):
    def test_only_existing_unambiguous_saved_network_is_selected(self):
        self.assertEqual(sole_saved_ssid("0   Test Wi Fi     wpa2-psk\n0   Test Wi Fi     wpa3-sae^"), "Test Wi Fi")
        self.assertIsNone(sole_saved_ssid("0   One     wpa2\n1   Two     wpa3"))

    def test_ui_selects_exact_ssid_not_unrelated_network(self):
        xml = '<hierarchy><node text="Other" bounds="[0,0][20,20]"/><node text="Saved" bounds="[10,20][30,60]"/></hierarchy>'
        self.assertEqual(saved_network_center(xml, "Saved"), (20, 40))
        self.assertIsNone(saved_network_center(xml, "Unknown"))

    def test_reconnection_retries_empty_scan_without_reading_credentials(self):
        calls = []
        xml = iter(('<hierarchy/>', '<hierarchy><node text="Saved" bounds="[10,20][30,60]"/></hierarchy>'))

        def adb(*values, check=True):
            calls.append(values)
            return next(xml) if values[0] == 'exec-out' else ''

        with patch('benchmark_device_network.time.sleep'):
            self.assertFalse(reconnect_saved_network(adb, 'Saved'))
            self.assertTrue(reconnect_saved_network(adb, 'Saved'))
        taps = [values for values in calls if values[:3] == ('shell', 'input', 'tap')]
        self.assertEqual(taps, [('shell', 'input', 'tap', '20', '40')])
        self.assertFalse(any('password' in str(values).lower() for values in calls))
