#!/usr/bin/env python3
"""Offline tests only: no ADB, sudo, network shaping, or benchmark observations."""

import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import benchmark_rtt_network as network

ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load("rtt_matrix_test", "run-rtt-cache-matrix.py")
summary = load("rtt_summary_test", "summarize-rtt-cache-results.py")


class MatrixTest(unittest.TestCase):
    def test_complete_matrix_and_static_baselines(self):
        cells = matrix.plan([0, 20, 50, 100, 200], 2, 2027)
        self.assertEqual(len(cells), 5 * 4 * 2 * 8 * 2)
        self.assertEqual(len({cell["file"] for cell in cells}), len(cells))
        self.assertEqual(cells, matrix.plan([0, 20, 50, 100, 200], 2, 2027))
        for offset in range(0, len(cells), 8):
            self.assertEqual(cells[offset]["Scheme"], "TLS")
            self.assertEqual(cells[offset]["Cache"], "none")
            group = cells[offset:offset + 8]
            self.assertEqual({row["Mode"] for row in group}, {"primary", "scp", "dcp", "compatible"})
            self.assertEqual({row["Cache"] for row in group if row["Scheme"] == "SCP"}, {"static"})

    def test_bad_dimensions(self):
        for values in ([], [0, 0], [-1], [2001]):
            with self.assertRaises(ValueError):
                matrix.plan(values, 1, 0)
        with self.assertRaises(ValueError):
            matrix.plan([0], 0, 0)

    def test_network_allocation_skips_existing_routes(self):
        routes = mock.Mock(stdout=json.dumps([{"dst": "198.18.0.0/30"}, {"dst": "default"}]))
        with mock.patch.object(network, "run", return_value=routes), \
                mock.patch.object(network.secrets, "randbelow", side_effect=[0, 1]):
            self.assertEqual(str(network.available_subnet()), "198.18.0.4/30")

    def test_no_synthetic_success_for_incomplete_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.fixture(temporary)
            path.unlink()
            with self.assertRaises(ValueError):
                summary.summarize(Path(temporary))

    def test_only_new_veth_is_shaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            link = network.IsolatedRttLink(Path(temporary), Path(temporary) / "evidence")
            try:
                with mock.patch.object(network, "run", return_value=mock.Mock(stdout="[]")) as command:
                    link.set_rtt(100)
                    calls = command.call_args_list
                    self.assertEqual(len(calls), 2)
                    self.assertIn(link.host_interface, calls[0].args)
                    self.assertIn(link.namespace, calls[1].args)
                    self.assertIn(link.peer_interface, calls[1].args)
                    for call in calls:
                        self.assertNotIn("lo", call.args)
                        self.assertNotIn("eth0", call.args)
                        self.assertIn("50ms", call.args)
            finally:
                link.close()

    def fixture(self, temporary, *, outcome="accepted", cache="hot", tk="0", tc="0"):
        path = Path(temporary) / "rtt-test.csv"
        cell = {"Algorithm": "es256", "Mode": "primary", "Scheme": "ASPin",
                "Phase": "real", "Cache": cache, "Added_RTT_ms": 20, "Repeat": 1,
                "file": path.name}
        rows = []
        for index, duration in enumerate((1, 2, 100), start=1):
            row = {field: str(cell[field]) for field in summary.DIMENSIONS + ("Repeat",)}
            row.update({field: "0.1" for field in summary.TIMINGS})
            row.update({"Sample": str(index), "Outcome_ms": str(duration),
                        "Outcome": outcome, "Expected_Outcome": "accepted", "Result": "PASS",
                        "Cache_Evidence": "hot-no-fetch" if cache == "hot" else "two-token-refresh",
                        "Tk_ms": tk, "Tc_ms": tc})
            rows.append(row)
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        (Path(temporary) / "matrix.json").write_text(json.dumps({"cells": [cell], "iterations": 3}))
        return path, cell

    def test_raw_percentiles_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.fixture(temporary)
            output = summary.summarize(Path(temporary))
            with output.open() as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(float(row["Outcome_P50_ms"]), 2)
            self.assertEqual(float(row["Outcome_P95_ms"]), 100)
            self.assertEqual(int(row["Samples"]), 3)

    def test_network_error_cannot_pass_as_rejection_or_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, cell = self.fixture(temporary, outcome="network_error")
            with self.assertRaises(ValueError):
                summary.validate_cell(path, cell, 3)

    def test_partial_refresh_is_not_cold(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, cell = self.fixture(temporary, cache="cold-forced-refresh", tk="0", tc="1")
            with self.assertRaises(ValueError):
                summary.validate_cell(path, cell, 3)

    def test_hot_fetch_is_not_a_cache_hit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, cell = self.fixture(temporary, tk="1")
            with self.assertRaises(ValueError):
                summary.validate_cell(path, cell, 3)

    def test_missing_observations_are_not_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, cell = self.fixture(temporary)
            with self.assertRaises(ValueError):
                summary.validate_cell(path, cell, 4)


if __name__ == "__main__":
    unittest.main()
