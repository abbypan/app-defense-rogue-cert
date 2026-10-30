import unittest
from benchmark_device_network import sole_saved_ssid, saved_network_center


class ReadinessTest(unittest.TestCase):
    def test_only_existing_unambiguous_saved_network_is_selected(self):
        self.assertEqual(sole_saved_ssid("0   Test Wi Fi     wpa2-psk\n0   Test Wi Fi     wpa3-sae^"), "Test Wi Fi")
        self.assertIsNone(sole_saved_ssid("0   One     wpa2\n1   Two     wpa3"))

    def test_ui_selects_exact_ssid_not_unrelated_network(self):
        xml = '<hierarchy><node text="Other" bounds="[0,0][20,20]"/><node text="Saved" bounds="[10,20][30,60]"/></hierarchy>'
        self.assertEqual(saved_network_center(xml, "Saved"), (20, 40))
        self.assertIsNone(saved_network_center(xml, "Unknown"))
