#!/usr/bin/env python3
"""Aggregate interleaved Boolean benchmark evidence from one runner."""

from __future__ import annotations

import argparse
import json
import math
import platform
import re
import statistics
from pathlib import Path

TFHE_RS_COMMIT = "640911eba7a394f078fa5d7d14e146105757e34f"
PARAMETERS = ("boolean-110", "boolean-128")
STAGE_NAMES = (
    "key_generation_us", "pbs_with_ks_us", "pbs_without_ks_us",
    "ksk_generation_us", "ksk_apply_us", "bsk_coefficient_generation_us",
    "bsk_fourier_conversion_us", "polynomial_multiplication_us",
    "external_product_us", "blind_rotation_us", "sample_extraction_us",
    "nand_us", "and_us", "or_us", "xor_us", "xnor_us", "mux_us",
)


def json_records(path: Path, kind: str | None = None) -> list[dict]:
    records = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("{"):
            record = json.loads(line)
            if kind is None or record.get("kind") == kind:
                records.append(record)
    if not records:
        raise ValueError(f"no {kind or 'JSON'} record in {path}")
    return records


def json_records_glob(directory: Path, prefix: str, kind: str) -> list[dict]:
    records: list[dict] = []
    for path in sorted(directory.glob(f"{prefix}*.jsonl")):
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("{"):
                record = json.loads(line)
                if record.get("kind") == kind:
                    records.append(record)
    if not records:
        raise ValueError(f"no {kind} records matching {prefix}*.jsonl")
    return records


def number(value: object, field: str, allow_null: bool = False) -> float | None:
    if value is None and allow_null:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{field} is not numeric")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{field} must be finite and positive")
    return result


def summary(values: list[float]) -> dict:
    ordered = sorted(values)
    p95 = ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]
    median = statistics.median(ordered)
    mad = statistics.median([abs(value - median) for value in ordered])
    return {"median": median, "p95": p95, "mad": mad, "samples": len(values)}


def aggregate(records: list[dict], field: str, path: str) -> float:
    values = []
    for record in records:
        value: object = record
        for component in field.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(component)
        values.append(number(value, f"{path}.{field}"))
    return float(statistics.median(values))


def aggregate_impl(records: list[dict], path: str) -> dict:
    first = records[0]
    gate_records = records[:7]
    result = {
        "schema_version": 3,
        "kind": "performance",
        "implementation": first.get("implementation"),
        "parameter": first.get("parameter"),
        "warmup": first.get("warmup"),
        "iterations": first.get("iterations"),
        "keygen_us": aggregate(records, "keygen_us", path),
        "pbs_us": aggregate(gate_records, "pbs_us", path),
        "nand_us": aggregate(gate_records, "nand_us", path),
        "stage_metrics": {},
    }
    for stage in STAGE_NAMES:
        stage_records = records if stage == "key_generation_us" else gate_records
        values = [record.get("stage_metrics", {}).get(stage) for record in stage_records]
        if all(value is None for value in values):
            result["stage_metrics"][stage] = None
        elif any(value is None for value in values):
            raise ValueError(f"{path}.stage_metrics.{stage} is inconsistently reported")
        else:
            result["stage_metrics"][stage] = aggregate(stage_records, f"stage_metrics.{stage}", path)
    result["statistics"] = {
        "keygen_us": summary([aggregate_value(record, "keygen_us", path) for record in records]),
        "pbs_us": summary([aggregate_value(record, "pbs_us", path) for record in gate_records]),
        "nand_us": summary([aggregate_value(record, "nand_us", path) for record in gate_records]),
    }
    if first.get("implementation") == "moontfhe":
        result["memory_metrics"] = {
            key: max(
                number(record.get("tracked_memory", {}).get(key), f"{path}.tracked_memory.{key}")
                for record in records
            )
            for key in ("resident_bytes", "coefficient_bsk_bytes", "fourier_bsk_bytes", "ksk_bytes", "workspace_bytes")
        }
    return result


def aggregate_value(record: dict, field: str, path: str) -> float:
    value: object = record
    for component in field.split("."):
        if not isinstance(value, dict):
            value = None
            break
        value = value.get(component)
    result = number(value, f"{path}.{field}")
    assert result is not None
    return result


def peak_rss_kib(paths: list[Path]) -> int:
    values = []
    for path in paths:
        content = path.read_text()
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", content, re.IGNORECASE)
        divisor = 1
        if match is None:
            match = re.search(r"maximum resident set size:\s*(\d+)", content, re.IGNORECASE)
            divisor = 1024
        if match is None:
            match = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", content, re.IGNORECASE | re.MULTILINE)
            divisor = 1024
        if match is None:
            raise ValueError(f"maximum RSS is missing from {path}")
        values.append(max(1, int(match.group(1)) // divisor))
    return max(values)


def size_record(records: list[dict], path: str) -> dict:
    if len(records) != 1:
        raise ValueError(f"expected one serialized-size record for {path}")
    record = records[0]
    return {
        "server_key_bytes": int(number(record.get("server_key_bytes"), f"{path}.server_key_bytes")),
        "ciphertext_bytes": int(number(record.get("ciphertext_bytes"), f"{path}.ciphertext_bytes")),
    }


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
        moon_records = json_records_glob(args.input_dir, f"moontfhe-{parameter}-", "performance")
        rust_records = json_records_glob(args.input_dir, f"tfhe-rs-{parameter}-", "performance")
        for records, implementation in ((moon_records, "moontfhe"), (rust_records, "tfhe-rs")):
            if len(records) != 10:
                raise ValueError(f"{parameter}.{implementation} needs exactly 10 paired batches")
            if any(record.get("parameter") != parameter or record.get("implementation") != implementation for record in records):
                raise ValueError(f"parameter or implementation mismatch for {parameter}")
            if any(record.get("warmup") != 100 or record.get("iterations") != 100 for record in records):
                raise ValueError(f"{parameter} does not use the required 100/100 timing protocol")
        moon = aggregate_impl(moon_records, f"moontfhe-{parameter}")
        rust = aggregate_impl(rust_records, f"tfhe-rs-{parameter}")
        moon_size = size_record(
            json_records(args.input_dir / f"moontfhe-{parameter}-serialized-size.jsonl", "serialized-size"),
            f"moontfhe-{parameter}",
        )
        rust_size = size_record(
            json_records(args.input_dir / f"tfhe-rs-{parameter}-serialized-size.jsonl", "serialized-size"),
            f"tfhe-rs-{parameter}",
        )
        moon.update(moon_size)
        rust.update(rust_size)
        moon_alloc_records = json_records(args.input_dir / f"moontfhe-{parameter}-allocation.jsonl", "allocation")
        if len(moon_alloc_records) != 1 or moon_alloc_records[0].get("iterations") != 1000:
            raise ValueError(f"{parameter} does not contain 1000-iteration allocation evidence")
        moon["allocation_metrics"] = {
            "available": True,
            "steady_state_heap_allocations": moon_alloc_records[0].get("native_kernel_heap_allocations"),
            "iterations": moon_alloc_records[0].get("iterations"),
            "workspace_peak_bytes": moon_alloc_records[0].get("tracked_memory", {}).get("workspace_bytes"),
        }
        rust["allocation_metrics"] = {"available": False}
        moon["peak_rss_kib"] = peak_rss_kib(sorted(args.input_dir.glob(f"moontfhe-{parameter}-*.time")))
        rust["peak_rss_kib"] = peak_rss_kib(sorted(args.input_dir.glob(f"tfhe-rs-{parameter}-*.time")))
        moon_stages, rust_stages = moon["stage_metrics"], rust["stage_metrics"]
        stage_ratios = {
            stage: moon_stages[stage] / rust_stages[stage]
            for stage in STAGE_NAMES
            if rust_stages[stage] is not None
        }
        ratios = {
            "keygen": moon["keygen_us"] / rust["keygen_us"],
            "pbs": moon["pbs_us"] / rust["nand_us"],
            "nand": moon["nand_us"] / rust["nand_us"],
            "server_key_size": moon["server_key_bytes"] / rust["server_key_bytes"],
            "ciphertext_size": moon["ciphertext_bytes"] / rust["ciphertext_bytes"],
        }
        measurements.append({
            "parameter": parameter,
            "moontfhe": moon,
            "tfhe_rs": rust,
            "ratios": ratios,
            "stage_metrics": {"moontfhe": moon_stages, "tfhe_rs": rust_stages},
            "stage_ratios": stage_ratios,
            "allocation_metrics": {"moontfhe": moon["allocation_metrics"], "tfhe_rs": rust["allocation_metrics"]},
            "memory_metrics": {
                "moontfhe": {"peak_rss_kib": moon["peak_rss_kib"], **moon["memory_metrics"], "server_key_bytes": moon["server_key_bytes"], "ciphertext_bytes": moon["ciphertext_bytes"]},
                "tfhe_rs": {"peak_rss_kib": rust["peak_rss_kib"], "server_key_bytes": rust["server_key_bytes"], "ciphertext_bytes": rust["ciphertext_bytes"]},
            },
        })
    max_nand = max(item["ratios"]["nand"] for item in measurements)
    max_pbs = max(item["ratios"]["pbs"] for item in measurements)
    max_execution = max(max_nand, max_pbs)
    score = 15 if max_execution <= 2 else 12 if max_execution <= 5 else 8 if max_execution <= 10 else 0
    evidence = {
        "schema_version": 3,
        "status": "measured",
        "repository_commit": args.repository_commit,
        "tfhe_rs_commit": TFHE_RS_COMMIT,
        "runner": {"label": args.runner, "system": platform.system(), "machine": platform.machine()},
        "method": {"same_runner": True, "interleaved_by_parameter": True, "gate_batches": 7, "keygen_batches": 10, "warmup_per_batch": 100, "iterations_per_batch": 100, "time_unit": "microseconds", "memory_unit": "KiB", "statistics": "median, p95 and median absolute deviation; RSS is maximum across samples"},
        "measurements": measurements,
        "performance": {"maximum_nand_ratio": max_nand, "maximum_pbs_ratio": max_pbs, "maximum_execution_ratio": max_execution, "score": score, "nand_within_5x": max_nand <= 5, "pbs_within_5x": max_pbs <= 5},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
