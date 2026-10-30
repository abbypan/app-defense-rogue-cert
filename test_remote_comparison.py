#!/usr/bin/env python3
"""Offline matrix/result checks; does not access a device or remote host."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("remote_comparison", ROOT / "run-remote-comparison.py")
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class RemoteComparisonTest(unittest.TestCase):
    def test_complete_independent_modes(self):
        cells = MATRIX.plan()
        self.assertEqual(len(cells), 64)
        self.assertEqual(len({cell["scenario"] for cell in cells}), 64)
        self.assertEqual({cell["mode"] for cell in cells}, {"primary", "scp", "dcp", "compatible"})
        for cell in cells:
            if cell["scheme"] == "DCP": self.assertEqual(cell["suffix"], "-dcp")
            if cell["scheme"] == "ASPin-compatible": self.assertEqual(cell["suffix"], "-compatible")

    def row(self):
        cell = next(cell for cell in MATRIX.plan() if cell["scheme"] == "DCP" and cell["phase"] == "rogue")
        row = {"Scenario": cell["scenario"], "Scheme": cell["scheme"], "Mode": cell["mode"],
               "Algorithm": cell["algorithm"], "Phase": cell["phase"], "Cache": cell["cache"],
               "Sample": "1", "Outcome": "policy_rejected", "Expected_Outcome": "policy_rejected",
               "Result": "PASS", "App_Request_Sent": "false"}
        row.update({field: "0" for field in ("Policy_ms", "Connection_ms", "Outcome_ms", "AppRead_ms", "Tk_ms", "Tc_ms")})
        return cell, row

    def test_policy_rejection_not_network_error(self):
        cell, row = self.row()
        self.assertEqual(MATRIX.validate([row], cell, 1), "policy_rejected")
        for field, value in (("Outcome", "network_error"), ("App_Request_Sent", "true"), ("Result", "FAIL")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                MATRIX.validate([row | {field: value}], cell, 1)

    def test_partial_and_substituted_mode_not_success(self):
        cell, row = self.row()
        with self.assertRaises(ValueError): MATRIX.validate([row], cell, 2)
        with self.assertRaises(ValueError): MATRIX.validate([row | {"Mode": "compatible"}], cell, 1)
        with self.assertRaises(ValueError): MATRIX.validate([row | {"Outcome_ms": "nan"}], cell, 1)

    def test_repeated_runs_cannot_reuse_audit_tags(self):
        first = {cell["scenario"] for cell in MATRIX.plan("run1")}
        second = {cell["scenario"] for cell in MATRIX.plan("run2")}
        self.assertFalse(first & second)

    def test_audit_requires_each_measured_request_once(self):
        cell = MATRIX.plan("unique")[0]
        def event(i):
            return {"path": "/", "observation": cell["scenario"] + "-" + str(i), "status": 200}
        self.assertTrue(MATRIX.audit_requests([event(1), event(2)], cell, 2, 0, "accepted")[0])
        self.assertFalse(MATRIX.audit_requests([event(1), event(1)], cell, 2, 0, "accepted")[0])
        self.assertFalse(MATRIX.audit_requests([event(1)], cell, 2, 0, "policy_rejected")[0])

    def test_explicit_network_failure_recording_is_not_a_pass(self):
        cell, row = self.row()
        failed = row | {"Outcome": "network_error", "Result": "FAIL", "Error_Class": "java.net.SocketException"}
        with self.assertRaises(ValueError): MATRIX.validate([failed], cell, 1)
        MATRIX.validate([failed], cell, 1, record_transport_failures=True)
        with self.assertRaises(ValueError):
            MATRIX.validate([failed | {"Result": "PASS"}], cell, 1, record_transport_failures=True)


if __name__ == "__main__":
    unittest.main()
