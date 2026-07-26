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
        ratios = {
            "keygen": moon["keygen_us"] / rust["keygen_us"],
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
            }
        )
    max_nand_ratio = max(item["ratios"]["nand"] for item in measurements)
    if max_nand_ratio <= 2.0:
        performance_score = 15
    elif max_nand_ratio <= 5.0:
        performance_score = 12
    elif max_nand_ratio <= 10.0:
        performance_score = 8
    else:
        performance_score = 0
    evidence = {
        "schema_version": 1,
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
        },
        "measurements": measurements,
        "performance": {
            "maximum_nand_ratio": max_nand_ratio,
            "score": performance_score,
            "nand_within_5x": max_nand_ratio <= 5.0,
            "nand_within_10x": max_nand_ratio <= 10.0,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
