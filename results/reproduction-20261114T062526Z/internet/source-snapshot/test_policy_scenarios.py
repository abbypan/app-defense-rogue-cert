#!/usr/bin/env python3
"""Synthetic validation fixtures only; never device measurements."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import benchmark_rtt_network as network

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("policy_scenarios_test", ROOT / "run-policy-scenario-matrix.py")
scenarios = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scenarios)


class PolicyScenariosTest(unittest.TestCase):
    def row(self, cell):
        accepted = cell["Expected_Outcome"] == "accepted"
        tls = cell["Expected_Outcome"] != "lookup_refused"
        lookup = cell["Operation"] == "protected" and tls
        cache = cell["cache"] if cell["cache"] != "any" else "none"
        return dict(Scenario=cell["Scenario"], Caller=cell["Caller"], API=cell["API"], Target=cell["Target"],
                    Operation=cell["Operation"], Force_Refresh=str(cell["force"]).lower(),
                    Lookup_Succeeded=str(lookup).lower(), Cache=cache,
                    Lookup_Start_ms="1000", Issued_ms="1000" if lookup else "0", Expires_ms="61000" if lookup else "0",
                    Tk_ms="1" if cache == "two-token-refresh" else "0", Tc_ms="2" if cache == "two-token-refresh" else "0",
                    Policy_ms="3", Outcome_ms="4", TLS_Attempted=str(tls).lower(), App_Request_Sent=str(accepted).lower(),
                    Outcome=cell["Expected_Outcome"], Expected_Outcome=cell["Expected_Outcome"], Result="PASS",
                    Error_Class="", Error_Message="")

    def test_both_modes_and_both_expiration_bounds(self):
        cells = scenarios.plan(2)
        self.assertEqual(len(cells), 188)
        self.assertEqual(len({c["Scenario"] for c in cells}), 188)
        for mode in ("primary", "compatible"):
            for group in ("tk-bound", "tc-bound"):
                subset = [c for c in cells if c["Mode"] == mode and c["Group"] == group]
                self.assertEqual({c["API"] for c in subset}, {"self", "cross"})
                self.assertEqual({c["error"] for c in subset}, {"none", "metadata-503", "expired-replay", "metadata-timeout", "debug-egress-denied"})

    def test_native_controls_and_target_identity_negatives(self):
        cells = scenarios.plan(1)
        self.assertTrue(any(c["name"] == "cross-invisible" and c["Caller"] == scenarios.HIDDEN for c in cells))
        for cell in cells:
            if cell["Operation"] == "native":
                self.assertEqual(cell["Expected_Outcome"], "accepted")
            scenarios.validate_row(self.row(cell), cell)

    def test_unrelated_errors_never_pass(self):
        cell = next(c for c in scenarios.plan(1) if c["name"] == "expired-self")
        row = self.row(cell); row["Outcome"] = "unexpected_error"
        with self.assertRaises(ValueError): scenarios.validate_row(row, cell)

    def test_lookup_failure_cannot_start_tls_or_send_data(self):
        cell = next(c for c in scenarios.plan(1) if c["name"] == "expired-self")
        for field in ("TLS_Attempted", "App_Request_Sent", "Lookup_Succeeded"):
            row = self.row(cell); row[field] = "true"
            with self.assertRaises(ValueError): scenarios.validate_row(row, cell)

    def test_caller_or_target_substitution_rejected_by_validator(self):
        cell = next(c for c in scenarios.plan(1) if c["name"] == "cross-target-hot")
        for field in ("Caller", "API", "Target"):
            row = self.row(cell); row[field] = "wrong"
            with self.assertRaises(ValueError): scenarios.validate_row(row, cell)

    def test_hot_cache_and_expiry_evidence_required(self):
        cell = next(c for c in scenarios.plan(1) if c["name"] == "cross-target-hot")
        row = self.row(cell); row["Tc_ms"] = "0.5"
        with self.assertRaises(ValueError): scenarios.validate_row(row, cell)
        row = self.row(cell); row["Expires_ms"] = "1000"
        with self.assertRaises(ValueError): scenarios.validate_row(row, cell)
        cell = dict(cell, not_before_ms=1001)
        with self.assertRaises(ValueError): scenarios.validate_row(self.row(cell), cell)

    def test_complete_plan_and_server_audit_required(self):
        cells = scenarios.plan(1)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "matrix.json").write_text(json.dumps(dict(cells=cells)))
            for cell in cells:
                row = self.row(cell)
                with (directory / cell["file"]).open("w", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(row)); writer.writeheader(); writer.writerow(row)
                (directory / f"{cell['Scenario']}.audit.json").write_text(json.dumps(dict(
                    Scenario=cell["Scenario"], Observed_App_Requests=1 if row["Outcome"] == "accepted" else 0)))
            self.assertTrue(scenarios.summarize(directory).is_file())
            refused = next(c for c in cells if c["Expected_Outcome"] == "lookup_refused")
            audit_path = directory / f"{refused['Scenario']}.audit.json"
            audit_path.write_text(json.dumps(dict(Scenario=refused["Scenario"], Observed_App_Requests=1)))
            with self.assertRaises(ValueError): scenarios.summarize(directory)
            (directory / refused["file"]).unlink()
            with self.assertRaises(ValueError): scenarios.summarize(directory)

    def test_metadata_fault_is_scoped_to_well_known(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            link = network.IsolatedRttLink(directory, directory / "evidence")
            try:
                for algorithm in network.ALGORITHMS:
                    for name in (f"authorized-{algorithm}-fullchain.pem", f"authorized-{algorithm}.key"):
                        (directory / name).touch()
                for state, expected in (("503", "return 503;"),
                                        ("timeout", "proxy_pass http://127.0.0.1:19091;"),
                                        ("serve", "try_files $uri =404;")):
                    link.policy_transport = state
                    link.write_config("real")
                    config = link.config.read_text()
                    self.assertEqual(config.count("location /.well-known/"), 4)
                    self.assertEqual(config.count(expected), 4)
                    self.assertEqual(config.count("location / { return 200 'ASPin RTT benchmark OK"), 4)
                    self.assertIn("$http_x_aspin_observation", config)
                    self.assertIn(f"return 200 'real|{state}'", config)
                    self.assertNotIn("proxy_pass http://127.0.0.1:19091;", config.split("location / {")[1].split("}")[0])
            finally:
                link.close()


if __name__ == "__main__":
    unittest.main()
