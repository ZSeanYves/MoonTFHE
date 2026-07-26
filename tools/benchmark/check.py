#!/usr/bin/env python3
"""Validate benchmark evidence without accepting placeholder measurements."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

TFHE_RS_COMMIT = "640911eba7a394f078fa5d7d14e146105757e34f"
EXPECTED_PARAMETERS = {"boolean-110", "boolean-128"}
RSS_LIMIT_KIB = {"boolean-110": 256 * 1024, "boolean-128": 320 * 1024}


def positive_number(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{field} is not numeric")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise ValueError(f"{field} must be finite and positive")
    return result


def validate(path: Path, require_rc_performance: bool) -> None:
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1 or data.get("status") != "measured":
        raise ValueError("benchmark status must be measured schema v1")
    if data.get("tfhe_rs_commit") != TFHE_RS_COMMIT:
        raise ValueError("tfhe-rs commit is not pinned to the approved revision")
    method = data.get("method", {})
    if method.get("same_runner") is not True or method.get("interleaved_by_parameter") is not True:
        raise ValueError("benchmark is not a same-runner interleaved comparison")
    measurements = data.get("measurements")
    if not isinstance(measurements, list):
        raise ValueError("measurements must be an array")
    seen = set()
    maximum_nand_ratio = 0.0
    for item in measurements:
        parameter = item.get("parameter")
        if parameter not in EXPECTED_PARAMETERS or parameter in seen:
            raise ValueError(f"unexpected or duplicate parameter {parameter!r}")
        seen.add(parameter)
        moon = item.get("moontfhe", {})
        rust = item.get("tfhe_rs", {})
        for implementation, record in (("moontfhe", moon), ("tfhe_rs", rust)):
            for field in (
                "keygen_us",
                "nand_us",
                "server_key_bytes",
                "ciphertext_bytes",
                "peak_rss_kib",
            ):
                positive_number(record.get(field), f"{parameter}.{implementation}.{field}")
        if moon["peak_rss_kib"] > RSS_LIMIT_KIB[parameter]:
            raise ValueError(f"{parameter} exceeds the production peak RSS limit")
        reported = positive_number(item.get("ratios", {}).get("nand"), "ratios.nand")
        computed = moon["nand_us"] / rust["nand_us"]
        if not math.isclose(reported, computed, rel_tol=1e-9, abs_tol=1e-12):
            raise ValueError(f"{parameter} NAND ratio is inconsistent")
        maximum_nand_ratio = max(maximum_nand_ratio, computed)
    if seen != EXPECTED_PARAMETERS:
        raise ValueError(f"missing parameter measurements: {EXPECTED_PARAMETERS - seen}")
    performance = data.get("performance", {})
    if not math.isclose(
        positive_number(performance.get("maximum_nand_ratio"), "maximum_nand_ratio"),
        maximum_nand_ratio,
        rel_tol=1e-9,
        abs_tol=1e-12,
    ):
        raise ValueError("maximum NAND ratio is inconsistent")
    if require_rc_performance and maximum_nand_ratio > 5.0:
        raise ValueError(f"NAND ratio {maximum_nand_ratio:.3f} exceeds the RC 5x gate")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--require-rc-performance", action="store_true")
    args = parser.parse_args()
    validate(args.evidence, args.require_rc_performance)
    print(f"benchmark evidence verified: {args.evidence}")


if __name__ == "__main__":
    main()
