#!/usr/bin/env python3
"""Validate every planned cell and pool raw samples, never average percentiles."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import statistics


DIMENSIONS = ("Algorithm", "Mode", "Scheme", "Phase", "Cache", "Added_RTT_ms")
TIMINGS = ("Policy_ms", "Connection_ms", "Outcome_ms", "AppRead_ms", "Tk_ms", "Tc_ms",
           "Echo_RTT_P50_ms", "Echo_RTT_P95_ms")


def percentile(values: list[float], fraction: float) -> float:
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def validate_cell(path: Path, cell: dict, iterations: int, *, require_cache_audit=True) -> list[dict]:
    if path.name != cell["file"] or Path(cell["file"]).name != cell["file"]:
        raise ValueError("Result filename must be a plain basename")
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != iterations:
        raise ValueError(f"{path.name}: expected {iterations} observations, got {len(rows)}")
    for index, row in enumerate(rows, start=1):
        for field in DIMENSIONS + ("Repeat",):
            if row.get(field) != str(cell[field]):
                raise ValueError(f"{path.name}: incorrect {field}")
        if row.get("Sample") != str(index):
            raise ValueError(f"{path.name}: missing or duplicate sample number")
        expected = "policy_rejected" if cell["Phase"] == "rogue" and cell["Scheme"] != "TLS" else "accepted"
        if row.get("Outcome") != expected or row.get("Expected_Outcome") != expected or row.get("Result") != "PASS":
            raise ValueError(f"{path.name}: observation {index} did not reach {expected}")
        for field in TIMINGS:
            value = float(row[field])
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{path.name}: invalid {field}")
        cache = cell["Cache"]
        if cell["Scheme"] == "DCP":
            if row["Cache_Evidence"] != "server-audit-required":
                raise ValueError(f"{path.name}: invalid independent DCP evidence")
        elif cache == "hot":
            if row["Cache_Evidence"] != "hot-no-fetch" or float(row["Tk_ms"]) != 0 or float(row["Tc_ms"]) != 0:
                raise ValueError(f"{path.name}: hot cache included network retrieval")
        elif cache == "cold-forced-refresh":
            if row["Cache_Evidence"] != "two-token-refresh" or float(row["Tk_ms"]) <= 0 or float(row["Tc_ms"]) <= 0:
                raise ValueError(f"{path.name}: not a complete forced refresh")
        elif row["Cache_Evidence"] != "not-applicable":
            raise ValueError(f"{path.name}: static/no-policy baseline has dynamic cache evidence")
    if cell["Scheme"] == "DCP" and require_cache_audit:
        audit = json.loads(path.with_suffix(".cache.json").read_text())
        if (audit.get("result") != "PASS" or audit.get("scheme") != "DCP"
                or audit.get("metadata_requests") != audit.get("expected_requests")
                or audit.get("expected_requests", 0) <= 0):
            raise ValueError(f"{path.name}: DCP cache request-count audit failed")
    return rows


def summarize(run_dir: Path) -> Path:
    manifest = json.loads((run_dir / "matrix.json").read_text())
    cells = manifest["cells"]
    if not cells or len({cell["file"] for cell in cells}) != len(cells):
        raise ValueError("Matrix must contain unique cells")
    expected_names = {cell["file"] for cell in cells}
    actual_names = {path.name for path in run_dir.glob("rtt-*.csv")}
    if actual_names != expected_names:
        raise ValueError(f"Incomplete/unexpected matrix files: {sorted(expected_names ^ actual_names)}")
    grouped = {}
    for cell in cells:
        if Path(cell["file"]).name != cell["file"]:
            raise ValueError("Unsafe result filename")
        rows = validate_cell(run_dir / cell["file"], cell, manifest["iterations"])
        key = tuple(str(cell[field]) for field in DIMENSIONS)
        grouped.setdefault(key, []).extend(rows)
    output = run_dir / "table_rtt_cache.csv"
    fields = DIMENSIONS + ("Samples", "Repeats", "Accepted", "Policy_Rejected",
                           "Outcome_Mean_ms", "Outcome_P50_ms", "Outcome_P95_ms", "Outcome_P99_ms",
                           "Policy_Mean_ms", "Connection_Mean_ms", "AppRead_Mean_ms",
                           "Echo_RTT_P50_Mean_ms", "Echo_RTT_P95_Max_ms", "Result")
    pending = output.with_suffix(".pending")
    with pending.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fields, lineterminator="\n")
        writer.writeheader()
        for key, rows in sorted(grouped.items(), key=lambda item: (int(item[0][-1]), item[0][:-1])):
            durations = [float(row["Outcome_ms"]) for row in rows]
            writer.writerow(dict(zip(DIMENSIONS, key)) | {
                "Samples": len(rows), "Repeats": len({row["Repeat"] for row in rows}),
                "Accepted": sum(row["Outcome"] == "accepted" for row in rows),
                "Policy_Rejected": sum(row["Outcome"] == "policy_rejected" for row in rows),
                "Outcome_Mean_ms": f"{statistics.mean(durations):.6f}",
                **{f"Outcome_P{p}_ms": f"{percentile(durations, p / 100):.6f}" for p in (50, 95, 99)},
                "Policy_Mean_ms": f"{statistics.mean(float(row['Policy_ms']) for row in rows):.6f}",
                "Connection_Mean_ms": f"{statistics.mean(float(row['Connection_ms']) for row in rows):.6f}",
                "AppRead_Mean_ms": f"{statistics.mean(float(row['AppRead_ms']) for row in rows):.6f}",
                "Echo_RTT_P50_Mean_ms": f"{statistics.mean(float(row['Echo_RTT_P50_ms']) for row in rows):.6f}",
                "Echo_RTT_P95_Max_ms": f"{max(float(row['Echo_RTT_P95_ms']) for row in rows):.6f}",
                "Result": "PASS",
            })
    pending.replace(output)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    arguments = parser.parse_args()
    print(summarize(arguments.run_dir))
