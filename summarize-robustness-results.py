#!/usr/bin/env python3
"""Validate a robustness run and produce compact Evaluation-ready CSV tables."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ALGORITHMS = ("es256", "es384", "rsa3072", "rsa4096")
ALGORITHM_LABELS = {
    "es256": "ES256",
    "es384": "ES384",
    "rsa3072": "PS256",
    "rsa4096": "PS384",
}
SCHEMES = {
    "TLS": ("StandardTLS", "TLS_Success_Standard"),
    "ASPin": ("ASPin", "TLS_Success_ASPin"),
    "SCP": ("SCP", "TLS_Success_SCP"),
    "DCP": ("DCP", "TLS_Success_DCP"),
}


def read_one(path: Path, result_column: str = "Result") -> dict[str, str]:
    if not path.is_file():
        raise SystemExit(f"Missing benchmark result: {path}")
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 1:
        raise SystemExit(f"{path}: expected one result row, found {len(rows)}")
    row = rows[0]
    if row.get(result_column) != "PASS":
        raise SystemExit(
            f"{path}: {result_column}={row.get(result_column)!r}, expected 'PASS'"
        )
    return row


def require(row: dict[str, str], fields: tuple[str, ...], source: Path) -> None:
    missing = [field for field in fields if field not in row or row[field] == ""]
    if missing:
        raise SystemExit(f"{source}: missing required fields: {', '.join(missing)}")


def write_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def summarize_refresh(run_dir: Path) -> None:
    output_fields = (
        "Algorithm",
        "Iterations",
        "Tk_Mean_ms",
        "Tc_Mean_ms",
        "ASPin_Total_Mean_ms",
        "ASPin_Total_P50_ms",
        "ASPin_Total_P95_ms",
        "ASPin_Total_P99_ms",
        "DCP_Mean_ms",
        "DCP_P50_ms",
        "DCP_P95_ms",
        "DCP_P99_ms",
        "ASPin_Success_Count",
        "DCP_Success_Count",
    )
    rows: list[dict[str, str]] = []
    for algorithm in ALGORITHMS:
        source = run_dir / f"cold-refresh-{algorithm}.csv"
        row = read_one(source)
        require(row, output_fields[1:], source)
        rows.append(
            {"Algorithm": ALGORITHM_LABELS[algorithm]}
            | {field: row[field] for field in output_fields[1:]}
        )
    write_rows(run_dir / "table_full_refresh_tail.csv", output_fields, rows)


def summarize_connections(run_dir: Path) -> None:
    output_fields = (
        "Phase",
        "Algorithm",
        "Scheme",
        "Iterations",
        "Mean_ms",
        "P95_ms",
        "P99_ms",
        "Successes",
    )
    rows: list[dict[str, str]] = []
    for phase, phase_label in (("real", "Real"), ("rogue", "Rogue")):
        for algorithm in ALGORITHMS:
            source = run_dir / f"cached-{phase}-{algorithm}.csv"
            row = read_one(source, "Matches_TeX_Design")
            require(row, ("Iterations",), source)
            for scheme, (prefix, success_field) in SCHEMES.items():
                required = (
                    f"{prefix}_Mean_ms",
                    f"{prefix}_P95_ms",
                    f"{prefix}_P99_ms",
                    success_field,
                )
                require(row, required, source)
                rows.append(
                    {
                        "Phase": phase_label,
                        "Algorithm": ALGORITHM_LABELS[algorithm],
                        "Scheme": scheme,
                        "Iterations": row["Iterations"],
                        "Mean_ms": row[f"{prefix}_Mean_ms"],
                        "P95_ms": row[f"{prefix}_P95_ms"],
                        "P99_ms": row[f"{prefix}_P99_ms"],
                        "Successes": row[success_field],
                    }
                )
    write_rows(run_dir / "table_connection_tail.csv", output_fields, rows)


def summarize_concurrency(run_dir: Path) -> None:
    output_fields = (
        "Mode",
        "Algorithm",
        "Operations",
        "Threads",
        "Successes",
        "Failures",
        "Mean_ms",
        "P50_ms",
        "P95_ms",
        "P99_ms",
        "Throughput_ops_s",
    )
    source_fields = output_fields[2:]
    rows: list[dict[str, str]] = []
    for algorithm in ALGORITHMS:
        source = run_dir / f"concurrent-cache-{algorithm}.csv"
        row = read_one(source)
        require(row, source_fields, source)
        rows.append(
            {"Mode": "Self", "Algorithm": ALGORITHM_LABELS[algorithm]}
            | {field: row[field] for field in source_fields}
        )
    source = run_dir / "cross-app-concurrent-cache.csv"
    row = read_one(source)
    require(row, source_fields, source)
    rows.append(
        {"Mode": "Cross-app", "Algorithm": "ES256"}
        | {field: row[field] for field in source_fields}
    )
    write_rows(run_dir / "table_concurrency.csv", output_fields, rows)


def summarize_lifecycle(run_dir: Path) -> None:
    names = (
        "lifecycle-v1-accepted.csv",
        "lifecycle-v2-accepted.csv",
        "post-restart-old-tc-replay.csv",
        "post-restart-old-tk-replay.csv",
        "post-restart-current-tokens.csv",
        "clock-rollback.csv",
        "clock-restored.csv",
        "cross-app-target-refresh.csv",
    )
    output_fields = (
        "Test",
        "ForceRefresh",
        "ExpectedSuccess",
        "ObservedSuccess",
        "ExpectedErrorSubstring",
        "ReasonMatch",
        "Total_ms",
        "Tk_ms",
        "Tc_ms",
        "Result",
    )
    rows: list[dict[str, str]] = []
    for name in names:
        source = run_dir / name
        row = read_one(source)
        required_nonempty = tuple(
            field for field in output_fields[1:] if field != "ExpectedErrorSubstring"
        )
        require(row, required_nonempty, source)
        if "ExpectedErrorSubstring" not in row:
            raise SystemExit(f"{source}: missing required field: ExpectedErrorSubstring")
        rows.append(
            {"Test": name.removesuffix(".csv")}
            | {field: row[field] for field in output_fields[1:]}
        )
    write_rows(run_dir / "table_lifecycle.csv", output_fields, rows)


def validate_additional_probes(run_dir: Path) -> None:
    parallel = read_one(run_dir / "parallel-cold-refresh.csv")
    require(
        parallel,
        ("First_ms", "Second_ms", "Wall_ms", "CombinedServiceWork_ms",
         "OverlapObserved"),
        run_dir / "parallel-cold-refresh.csv",
    )
    if parallel["OverlapObserved"].lower() != "true":
        raise SystemExit("parallel-cold-refresh.csv: refreshes did not overlap")

    expiry = read_one(run_dir / "delegation-expiry.csv")
    require(
        expiry,
        ("EffectiveExp_ms", "TkExp_ms", "TcExp_ms", "BoundMatches"),
        run_dir / "delegation-expiry.csv",
    )
    if expiry["BoundMatches"].lower() != "true":
        raise SystemExit("delegation-expiry.csv: returned expiration is not min(Tk,Tc)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="results/robustness-<timestamp>")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        raise SystemExit(f"Not a robustness result directory: {run_dir}")

    summarize_refresh(run_dir)
    summarize_connections(run_dir)
    summarize_concurrency(run_dir)
    summarize_lifecycle(run_dir)
    validate_additional_probes(run_dir)
    print(f"Validated robustness run and wrote summary tables under {run_dir}")


if __name__ == "__main__":
    main()
