#!/usr/bin/env python3
"""Validate measured Boolean benchmark evidence and release thresholds."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

TFHE_RS_COMMIT = "640911eba7a394f078fa5d7d14e146105757e34f"
EXPECTED_PARAMETERS = {"boolean-110", "boolean-128"}
RSS_LIMIT_KIB = {"boolean-110": 256 * 1024, "boolean-128": 320 * 1024}
STAGE_NAMES = {
    "key_generation_us", "pbs_with_ks_us", "pbs_without_ks_us", "ksk_generation_us",
    "ksk_apply_us", "bsk_coefficient_generation_us", "bsk_fourier_conversion_us",
    "polynomial_multiplication_us", "external_product_us", "blind_rotation_us",
    "external_product_count", "sample_extraction_us", "nand_us", "and_us", "or_us", "xor_us", "xnor_us", "mux_us",
}


def positive(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{field} is not numeric")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{field} must be finite and positive")
    return result


def validate_summary(summary: object, field: str, expected_samples: int) -> None:
    if not isinstance(summary, dict) or summary.get("samples") != expected_samples:
        raise ValueError(f"{field} does not contain {expected_samples} samples")
    median = positive(summary.get("median"), f"{field}.median")
    p95 = positive(summary.get("p95"), f"{field}.p95")
    mad = summary.get("mad")
    if not isinstance(mad, (int, float)) or isinstance(mad, bool) or not math.isfinite(mad) or mad < 0:
        raise ValueError(f"{field}.mad must be finite and non-negative")
    if p95 < median:
        raise ValueError(f"{field}.p95 is below its median")


def validate(path: Path, require_rc: bool, baseline: Path | None, max_regression: float) -> None:
    data = json.loads(path.read_text())
    if data.get("schema_version") != 3 or data.get("status") != "measured":
        raise ValueError("benchmark status must be measured schema v3")
    if data.get("tfhe_rs_commit") != TFHE_RS_COMMIT:
        raise ValueError("tfhe-rs commit is not pinned to the approved revision")
    method = data.get("method", {})
    expected_method = {
        "same_runner": True,
        "interleaved_by_parameter": True,
        "gate_batches": 7,
        "keygen_batches": 10,
        "warmup_per_batch": 100,
        "iterations_per_batch": 100,
    }
    if any(method.get(key) != value for key, value in expected_method.items()):
        raise ValueError("benchmark does not use the required interleaved 7/10 batch protocol")
    measurements = data.get("measurements")
    if not isinstance(measurements, list):
        raise ValueError("measurements must be an array")
    seen: set[str] = set()
    max_nand = max_pbs = max_keygen = max_other = 0.0
    for item in measurements:
        parameter = item.get("parameter")
        if parameter not in EXPECTED_PARAMETERS or parameter in seen:
            raise ValueError(f"unexpected or duplicate parameter {parameter!r}")
        seen.add(parameter)
        moon, rust = item.get("moontfhe", {}), item.get("tfhe_rs", {})
        for implementation, record in (("moontfhe", moon), ("tfhe_rs", rust)):
            if record.get("schema_version") != 3 or record.get("kind") != "performance":
                raise ValueError(f"{parameter}.{implementation} is not schema-v3 performance evidence")
            if record.get("warmup") != 100 or record.get("iterations") != 100:
                raise ValueError(f"{parameter}.{implementation} timing protocol is wrong")
            for field in ("keygen_us", "pbs_us", "nand_us", "server_key_bytes", "ciphertext_bytes", "peak_rss_kib"):
                positive(record.get(field), f"{parameter}.{implementation}.{field}")
            stats = record.get("statistics", {})
            validate_summary(stats.get("keygen_us"), f"{parameter}.{implementation}.keygen", 10)
            validate_summary(stats.get("pbs_us"), f"{parameter}.{implementation}.pbs", 7)
            validate_summary(stats.get("nand_us"), f"{parameter}.{implementation}.nand", 7)
            stages = record.get("stage_metrics")
            if not isinstance(stages, dict) or set(stages) != STAGE_NAMES:
                raise ValueError(f"{parameter}.{implementation}.stage_metrics has the wrong shape")
            for stage, value in stages.items():
                if implementation == "moontfhe" or value is not None:
                    positive(value, f"{parameter}.{implementation}.{stage}")
            if implementation == "moontfhe":
                gate_counts = record.get("gate_pbs_counts")
                expected_counts = {"nand": 1, "and": 1, "or": 1, "xor": 1, "xnor": 1, "mux": 2}
                if gate_counts != expected_counts:
                    raise ValueError(f"{parameter}.moontfhe.gate_pbs_counts does not match the fixed Boolean LUT contract")
        allocations = moon.get("allocation_metrics", {})
        if allocations.get("available") is not True or allocations.get("iterations") != 1000:
            raise ValueError(f"{parameter} lacks 1,000-call allocator evidence")
        count = allocations.get("steady_state_heap_allocations")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"{parameter} allocator count is not a measured integer")
        positive(allocations.get("workspace_peak_bytes"), f"{parameter}.workspace_peak_bytes")
        memory = moon.get("memory_metrics", {})
        for field in ("resident_bytes", "coefficient_bsk_bytes", "fourier_bsk_bytes", "ksk_bytes", "workspace_bytes"):
            positive(memory.get(field), f"{parameter}.memory_metrics.{field}")
        ratios = item.get("ratios", {})
        computed = {
            "keygen": moon["keygen_us"] / rust["keygen_us"],
            "pbs": moon["pbs_us"] / rust["nand_us"],
            "nand": moon["nand_us"] / rust["nand_us"],
            "server_key_size": moon["server_key_bytes"] / rust["server_key_bytes"],
            "ciphertext_size": moon["ciphertext_bytes"] / rust["ciphertext_bytes"],
        }
        for name, value in computed.items():
            reported = positive(ratios.get(name), f"{parameter}.ratios.{name}")
            if not math.isclose(reported, value, rel_tol=1e-9, abs_tol=1e-12):
                raise ValueError(f"{parameter}.{name} ratio is inconsistent")
        stage_ratios = item.get("stage_ratios", {})
        for stage, rust_value in rust["stage_metrics"].items():
            if rust_value is None:
                if stage in stage_ratios:
                    raise ValueError(f"{parameter}.{stage} has no comparable tfhe-rs baseline")
                continue
            computed_stage = moon["stage_metrics"][stage] / rust_value
            if not math.isclose(positive(stage_ratios.get(stage), f"{parameter}.{stage}"), computed_stage, rel_tol=1e-9, abs_tol=1e-12):
                raise ValueError(f"{parameter}.{stage} ratio is inconsistent")
            if stage not in {"key_generation_us", "pbs_with_ks_us", "nand_us", "mux_us"}:
                max_other = max(max_other, computed_stage)
        max_keygen = max(max_keygen, computed["keygen"])
        max_pbs = max(max_pbs, computed["pbs"])
        max_nand = max(max_nand, computed["nand"])
        if require_rc:
            if count != 0:
                raise ValueError(f"{parameter} steady-state PBS made {count} heap allocations")
            if moon["peak_rss_kib"] > RSS_LIMIT_KIB[parameter]:
                raise ValueError(f"{parameter} exceeds the production peak RSS limit")
            mux_ratio = moon["stage_metrics"]["mux_us"] / rust["stage_metrics"]["mux_us"]
            if mux_ratio > 3:
                raise ValueError(f"{parameter} MUX ratio {mux_ratio:.3f} exceeds 3x")
    if seen != EXPECTED_PARAMETERS:
        raise ValueError(f"missing parameter measurements: {EXPECTED_PARAMETERS - seen}")
    performance = data.get("performance", {})
    for name, value in (("maximum_nand_ratio", max_nand), ("maximum_pbs_ratio", max_pbs), ("maximum_execution_ratio", max(max_nand, max_pbs))):
        if not math.isclose(positive(performance.get(name), name), value, rel_tol=1e-9, abs_tol=1e-12):
            raise ValueError(f"{name} is inconsistent")
    if require_rc:
        if max(max_nand, max_pbs, max_keygen) > 2:
            raise ValueError(f"PBS/NAND/keygen maximum ratio {max(max_nand, max_pbs, max_keygen):.3f} exceeds 2x")
        if max_other > 3:
            raise ValueError(f"comparable core-stage ratio {max_other:.3f} exceeds 3x")
    if baseline is not None:
        previous = json.loads(baseline.read_text())
        previous_by_parameter = {item["parameter"]: item for item in previous.get("measurements", [])}
        for item in measurements:
            old = previous_by_parameter.get(item["parameter"])
            if old is None:
                continue
            for metric in ("keygen", "pbs", "nand"):
                old_ratio = positive(old.get("ratios", {}).get(metric), f"baseline.{metric}")
                new_ratio = item["ratios"][metric]
                if new_ratio > old_ratio * (1 + max_regression):
                    raise ValueError(f"{item['parameter']}.{metric} regressed more than {max_regression:.0%}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--require-rc-performance", action="store_true")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--max-regression", type=float, default=0.10)
    args = parser.parse_args()
    validate(args.evidence, args.require_rc_performance, args.baseline, args.max_regression)
    print(f"benchmark evidence verified: {args.evidence}")


if __name__ == "__main__":
    main()
