#!/usr/bin/env python3
"""Collect same-runner MoonTFHE/tfhe-rs benchmark evidence."""

from __future__ import annotations

import argparse
import json
import platform
import re
from pathlib import Path

TFHE_RS_COMMIT = "640911eba7a394f078fa5d7d14e146105757e34f"
PARAMETERS = ("boolean-110", "boolean-128")
STAGE_NAMES = (
    "key_generation_us",
    "pbs_with_ks_us",
    "pbs_without_ks_us",
    "ksk_generation_us",
    "ksk_apply_us",
    "bsk_coefficient_generation_us",
    "bsk_fourier_conversion_us",
    "polynomial_multiplication_us",
    "external_product_us",
    "blind_rotation_us",
    "sample_extraction_us",
    "nand_us",
    "and_us",
    "or_us",
    "xor_us",
    "xnor_us",
    "mux_us",
)


def read_json_line(path: Path) -> dict:
    records = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("{"):
            records.append(json.loads(line))
    if len(records) != 1:
        raise ValueError(f"expected one JSON record in {path}, found {len(records)}")
    return records[0]


def read_peak_rss_kib(path: Path) -> int:
    match = re.search(
        r"Maximum resident set size \(kbytes\):\s*(\d+)", path.read_text()
    )
    if match is None:
        raise ValueError(f"maximum RSS is missing from {path}")
    return int(match.group(1))


def read_stage_metrics(record: dict, path: Path) -> dict:
    stages = record.get("stage_metrics")
    if not isinstance(stages, dict):
        raise ValueError(f"stage_metrics is missing from {path}")
    missing = [name for name in STAGE_NAMES if name not in stages]
    if missing:
        raise ValueError(f"stage_metrics missing {missing} in {path}")
    return {name: stages[name] for name in STAGE_NAMES}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--runner", default="github-actions-ubuntu-24.04")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    measurements = []
    for parameter in PARAMETERS:
        moon = read_json_line(args.input_dir / f"moontfhe-{parameter}.jsonl")
        rust = read_json_line(args.input_dir / f"tfhe-rs-{parameter}.jsonl")
        if moon.get("parameter") != parameter or rust.get("parameter") != parameter:
            raise ValueError(f"parameter mismatch for {parameter}")
        moon["peak_rss_kib"] = read_peak_rss_kib(
            args.input_dir / f"moontfhe-{parameter}.time"
        )
        rust["peak_rss_kib"] = read_peak_rss_kib(
            args.input_dir / f"tfhe-rs-{parameter}.time"
        )
        moon_stages = read_stage_metrics(moon, args.input_dir / f"moontfhe-{parameter}.jsonl")
        rust_stages = read_stage_metrics(rust, args.input_dir / f"tfhe-rs-{parameter}.jsonl")
        stage_ratios = {}
        for name in STAGE_NAMES:
            left = moon_stages[name]
            right = rust_stages[name]
            if isinstance(left, (int, float)) and isinstance(right, (int, float)) and right > 0:
                stage_ratios[name] = left / right
        ratios = {
            "keygen": moon["keygen_us"] / rust["keygen_us"],
            # A tfhe-rs Boolean NAND evaluates one bootstrapped gate. Its public
            # harness does not expose a standalone PBS timer, so it is the
            # closest stable same-runner baseline for MoonTFHE's direct PBS.
            "pbs": moon["pbs_us"] / rust["nand_us"],
            "nand": moon["nand_us"] / rust["nand_us"],
            "server_key_size": moon["server_key_bytes"] / rust["server_key_bytes"],
            "ciphertext_size": moon["ciphertext_bytes"] / rust["ciphertext_bytes"],
        }
        measurements.append(
            {
                "parameter": parameter,
                "moontfhe": moon,
                "tfhe_rs": rust,
                "ratios": ratios,
                "stage_metrics": {"moontfhe": moon_stages, "tfhe_rs": rust_stages},
                "stage_ratios": stage_ratios,
                "allocation_metrics": {
                    "moontfhe": moon.get("allocation_metrics", {"available": False}),
                    "tfhe_rs": rust.get("allocation_metrics", {"available": False}),
                },
                "memory_metrics": {
                    "moontfhe": {
                        "peak_rss_kib": moon["peak_rss_kib"],
                        "server_key_bytes": moon["server_key_bytes"],
                        "ciphertext_bytes": moon["ciphertext_bytes"],
                    },
                    "tfhe_rs": {
                        "peak_rss_kib": rust["peak_rss_kib"],
                        "server_key_bytes": rust["server_key_bytes"],
                        "ciphertext_bytes": rust["ciphertext_bytes"],
                    },
                },
            }
        )
    max_nand_ratio = max(item["ratios"]["nand"] for item in measurements)
    max_pbs_ratio = max(item["ratios"]["pbs"] for item in measurements)
    max_execution_ratio = max(max_nand_ratio, max_pbs_ratio)
    if max_execution_ratio <= 2.0:
        performance_score = 15
    elif max_execution_ratio <= 5.0:
        performance_score = 12
    elif max_execution_ratio <= 10.0:
        performance_score = 8
    else:
        performance_score = 0
    evidence = {
        "schema_version": 2,
        "status": "measured",
        "repository_commit": args.repository_commit,
        "tfhe_rs_commit": TFHE_RS_COMMIT,
        "runner": {
            "label": args.runner,
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "method": {
            "same_runner": True,
            "interleaved_by_parameter": True,
            "iterations_per_gate": 10,
            "time_unit": "microseconds",
            "memory_unit": "KiB",
            "stage_metrics": "null means the implementation does not expose that internal stage",
            "pbs_baseline": "tfhe-rs Boolean NAND is one bootstrapped gate",
        },
        "measurements": measurements,
        "performance": {
            "maximum_nand_ratio": max_nand_ratio,
            "maximum_pbs_ratio": max_pbs_ratio,
            "maximum_execution_ratio": max_execution_ratio,
            "score": performance_score,
            "nand_within_5x": max_nand_ratio <= 5.0,
            "pbs_within_5x": max_pbs_ratio <= 5.0,
            "nand_within_10x": max_nand_ratio <= 10.0,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
