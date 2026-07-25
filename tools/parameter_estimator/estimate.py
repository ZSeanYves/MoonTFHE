#!/usr/bin/env python3
"""Run the pinned lattice-estimator with explicit MoonTFHE assumptions."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from estimator import LWE, ND
from sage.all import RealField, log, oo


ESTIMATOR_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
MODEL = "lattice-estimator-default-all-attacks"


def canonical_sha256(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def estimate_lwe(name: str, dimension: int, sigma_q32: int) -> dict:
    sigma = RealField(128)(sigma_q32) / (2**32)
    parameters = LWE.Parameters(
        n=dimension,
        q=2**32,
        Xs=ND.Binary,
        Xe=ND.DiscreteGaussian(stddev=sigma),
        m=oo,
        tag=name,
    )
    attacks = LWE.estimate(parameters, jobs=1, quiet=True)
    costs = {
        attack: round(float(log(result["rop"], 2)), 6)
        for attack, result in attacks.items()
        if result["rop"] != oo
    }
    if not costs:
        raise RuntimeError(f"{name}: estimator returned no finite attack")
    return {
        "dimension": dimension,
        "modulus": "2^32",
        "samples": "unlimited",
        "noise_sigma_q32": sigma_q32,
        "noise_stddev_torus_integer": round(float(sigma), 12),
        "attacks_log2_rop": dict(sorted(costs.items())),
        "security_bits": min(costs.values()),
    }


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: estimate.py INPUT_JSON")
    source = Path(sys.argv[1])
    data = json.loads(source.read_text())
    if data["estimator_commit"] != ESTIMATOR_COMMIT:
        raise ValueError("input estimator commit mismatch")
    if data["modulus"] != "2^32" or data["secret_distribution"] != "binary":
        raise ValueError("unsupported modulus or secret distribution")
    lwe_sigma_q32 = int(data["lwe_noise"]["sigma_q32"])
    glwe_sigma_q32 = int(data["glwe_noise"]["sigma_q32"])
    if lwe_sigma_q32 <= 0 or glwe_sigma_q32 <= 0:
        raise ValueError("quantized Gaussian sigma must be positive")
    lwe = estimate_lwe(
        "MoonTFHE LWE", int(data["lwe_dimension"]), lwe_sigma_q32
    )
    flattened_glwe_dimension = int(data["glwe_dimension"]) * int(
        data["polynomial_size"]
    )
    glwe = estimate_lwe(
        "MoonTFHE GLWE flattened as LWE",
        flattened_glwe_dimension,
        glwe_sigma_q32,
    )
    result = {
        "status": "lattice_verified_noise_pending",
        "parameter_id": data["parameter_id"],
        "security_bits": min(lwe["security_bits"], glwe["security_bits"]),
        "lwe_security": lwe,
        "glwe_security": glwe,
        "glwe_model_limitation": (
            "The fixed estimator has no native GLWE/RLWE model; this value uses "
            "the explicitly recorded flattened-LWE approximation and is not an "
            "independent ring-security proof."
        ),
        "failure_probability": None,
        "noise_margin": None,
        "noise_model_status": "pending_exact_pbs_ks_propagation",
        "estimator_model": MODEL,
        "estimator_commit": ESTIMATOR_COMMIT,
        "input_sha256": canonical_sha256(data),
        "generation_metadata": {
            "timestamp_independent": True,
            "sage_entrypoint": "sage -python",
            "cost_unit": "log2 ring operations",
        },
    }
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
