#!/usr/bin/env python3
"""Produce a stage-oriented profile from measured Boolean benchmark evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def profile_measurement(measurement: dict) -> dict:
    stages = measurement["moontfhe"]["stage_metrics"]
    pbs = float(stages["pbs_with_ks_us"])
    profile: dict[str, object] = {
        "parameter": measurement["parameter"],
        "pbs_with_ks_us": pbs,
        "gate_pbs_counts": measurement["moontfhe"].get("gate_pbs_counts"),
        "stages": {},
    }
    for name in (
        "pbs_without_ks_us",
        "ksk_apply_us",
        "blind_rotation_us",
        "sample_extraction_us",
        "polynomial_multiplication_us",
    ):
        value = stages.get(name)
        if value is not None:
            profile["stages"][name] = {
                "microseconds": float(value),
                "fraction_of_pbs": float(value) / pbs,
            }
    count = stages.get("external_product_count")
    external = stages.get("external_product_us")
    if count is not None and external is not None:
        total = float(count) * float(external)
        profile["stages"]["external_product_total_us"] = {
            "microseconds": total,
            "fraction_of_pbs": total / pbs,
            "per_product_us": float(external),
            "count": int(count),
        }
    profile["memory"] = measurement["memory_metrics"]["moontfhe"]
    return profile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = json.loads(args.evidence.read_text())
    if data.get("schema_version") != 3 or data.get("status") != "measured":
        raise SystemExit("profile input must be measured schema v3 evidence")
    report = {
        "schema_version": 1,
        "kind": "stage-profile",
        "source_schema_version": data["schema_version"],
        "repository_commit": data.get("repository_commit"),
        "tfhe_rs_commit": data.get("tfhe_rs_commit"),
        "profiles": [profile_measurement(item) for item in data["measurements"]],
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
