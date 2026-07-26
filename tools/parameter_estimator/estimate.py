#!/usr/bin/env python3
"""Run the pinned lattice-estimator with explicit MoonTFHE assumptions."""

from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path

from estimator import LWE, ND
from sage.all import RealField, log, oo


ESTIMATOR_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
MODEL = "lattice-estimator-default-all-attacks"
TFHE_RS_COMMIT = "640911eba7a394f078fa5d7d14e146105757e34f"
TORUS_BITS = 32
TORUS_MODULUS = 2.0**TORUS_BITS


def log2_sum(*values: float) -> float:
    finite = [value for value in values if math.isfinite(value)]
    if not finite:
        return -math.inf
    largest = max(finite)
    return largest + math.log2(sum(2.0 ** (value - largest) for value in finite))


def gaussian_log2_upper_bound(margin: float, variance: float) -> float:
    """Chernoff upper bound for a two-sided centered Gaussian tail."""
    if margin <= 0.0 or variance <= 0.0:
        return 0.0
    return 1.0 - margin * margin / (2.0 * variance * math.log(2.0))


def pbs_variance_132_gaussian_fft(
    input_lwe_dimension: int,
    output_glwe_dimension: int,
    output_polynomial_size: int,
    decomposition_base_log: int,
    decomposition_level_count: int,
    mantissa_size: int,
    modulus: float,
) -> float:
    """Pinned tfhe-rs Gaussian FFT PBS variance formula.

    This is copied as an executable formula from the fixed tfhe-rs commit,
    while all distribution values are supplied by MoonTFHE's fixtures.
    """
    n = float(input_lwe_dimension)
    k = float(output_glwe_dimension)
    big_n = float(output_polynomial_size)
    base = 2.0**decomposition_base_log
    level = float(decomposition_level_count)
    fft_term = 0.00705 * 2.0 ** (
        2.0
        * min(0.0, -float(mantissa_size) + math.log2(math.e) * math.log(modulus))
        + 2.88539008177793 * math.log(base)
        - 2.88539008177793 * math.log(modulus)
    )
    gaussian = (
        fft_term
        * level**1.01827
        * k**1.22003
        * big_n**2.22003
        * (k + 1.0) ** 1.01827
    )
    rounding = (
        level
        * big_n
        * (
            2.0 ** (4.0 - 2.88539008177793 * math.log(modulus))
            + 2.0 ** (-0.0497829131652661 * k * big_n + 5.31469187675068)
        )
        * (base * base / 12.0 + 1.0 / 6.0)
        * (k + 1.0)
    )
    return n * (
        gaussian
        + rounding
        - modulus ** -2 / 24.0
        + 0.5
        * k
        * big_n
        * (0.0208333333333333 * modulus ** -2 + 0.0416666666666667 * base ** (-2.0 * level))
        + base ** (-2.0 * level) / 24.0
    )


def keyswitch_variance_132_gaussian(
    input_lwe_dimension: int,
    output_lwe_dimension: int,
    decomposition_base_log: int,
    decomposition_level_count: int,
    input_modulus: float,
    output_modulus: float,
) -> float:
    """Pinned tfhe-rs Gaussian FFT KS additive variance formula."""
    n = float(input_lwe_dimension)
    out = float(output_lwe_dimension)
    base = 2.0**decomposition_base_log
    level = float(decomposition_level_count)
    return level * n * (
        (
            2.0 ** (4.0 - 2.88539008177793 * math.log(output_modulus))
            + 2.0 ** (5.31469187675068 - 0.0497829131652661 * out)
        )
        * (base * base / 12.0 + 1.0 / 6.0)
        + 0.0208333333333333 * input_modulus ** -2
        + 0.0416666666666667 * base ** (-2.0 * level)
    ) - input_modulus ** -2 / 12.0 + output_modulus ** -2 / 12.0


def noise_model(data: dict) -> dict:
    q = TORUS_MODULUS
    n = int(data["lwe_dimension"])
    k = int(data["glwe_dimension"])
    polynomial_size = int(data["polynomial_size"])
    pbs = data["pbs_decomposition"]
    ks = data["ks_decomposition"]
    lwe_sigma = float(data["lwe_noise"]["sigma_q32"]) / 2.0**64
    glwe_sigma = float(data["glwe_noise"]["sigma_q32"]) / 2.0**64
    pbs_variance = pbs_variance_132_gaussian(
        n,
        k,
        polynomial_size,
        int(pbs["base_log"]),
        int(pbs["level"]),
        int(data["fft_mantissa_bits"]),
        q,
    )
    ks_variance = keyswitch_variance_132_gaussian(
        k * polynomial_size,
        n,
        int(ks["base_log"]),
        int(ks["level"]),
        q,
        q,
    )
    output_variance = pbs_variance + ks_variance
    pre_pbs_margin = 2.0 ** float(data["boolean_encoding"]["pre_pbs_margin_log2"])
    decrypt_margin = 2.0 ** float(data["boolean_encoding"]["decrypt_margin_log2"])
    gate_norm_squared = float(data["boolean_encoding"]["max_gate_noise_norm_squared"])
    gaussian_pre_pbs = gaussian_log2_upper_bound(
        pre_pbs_margin, gate_norm_squared * output_variance
    )
    gaussian_decrypt = gaussian_log2_upper_bound(decrypt_margin, output_variance)
    gaussian_failure = log2_sum(gaussian_pre_pbs, gaussian_decrypt)

    bsk_noise_samples = n * int(pbs["level"]) * (k + 1) * polynomial_size
    ksk_noise_samples = k * polynomial_size * int(ks["level"])
    lwe_tv = float(data["lwe_noise"]["single_sample_tv_log2_upper"])
    glwe_tv = float(data["glwe_noise"]["single_sample_tv_log2_upper"])
    sampler_failure = log2_sum(
        math.log2(bsk_noise_samples) + glwe_tv,
        math.log2(ksk_noise_samples) + lwe_tv,
    )
    total_failure = log2_sum(gaussian_failure, sampler_failure)
    return {
        "status": "verified",
        "noise_model_status": "verified_fixed_point_union_bound",
        "variance_torus": {
            "pbs": pbs_variance,
            "keyswitch": ks_variance,
            "output": output_variance,
        },
        "noise_margin": {
            "pre_pbs_torus": pre_pbs_margin,
            "decrypt_torus": decrypt_margin,
            "output_sigma_torus": math.sqrt(output_variance),
            "pre_pbs_sigma_scale": pre_pbs_margin
            / math.sqrt(gate_norm_squared * output_variance),
            "decrypt_sigma_scale": decrypt_margin / math.sqrt(output_variance),
        },
        "failure_probability": {
            "log2_upper_bound": total_failure,
            "gaussian_log2_upper_bound": gaussian_failure,
            "sampler_statistical_distance_log2_upper_bound": sampler_failure,
            "bsk_noise_samples": bsk_noise_samples,
            "ksk_noise_samples": ksk_noise_samples,
            "union_bound": True,
        },
        "noise_model_source": {
            "tfhe_rs_commit": TFHE_RS_COMMIT,
            "pbs_formula": "core_crypto/commons/noise_formulas/lwe_programmable_bootstrap.rs",
            "keyswitch_formula": "core_crypto/commons/noise_formulas/lwe_keyswitch.rs",
            "distribution_distance": "MoonTFHE CDT fixture metadata",
        },
    }


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
        "status": "verified",
        "parameter_id": data["parameter_id"],
        "security_bits": min(lwe["security_bits"], glwe["security_bits"]),
        "lwe_security": lwe,
        "glwe_security": glwe,
        "glwe_model_limitation": (
            "The fixed estimator has no native GLWE/RLWE model; this value uses "
            "the explicitly recorded flattened-LWE approximation and is not an "
            "independent ring-security proof."
        ),
        "estimator_model": MODEL,
        "estimator_commit": ESTIMATOR_COMMIT,
        "input_sha256": canonical_sha256(data),
        "generation_metadata": {
            "timestamp_independent": True,
            "sage_entrypoint": "sage -python",
            "cost_unit": "log2 ring operations",
        },
    }
    result.update(noise_model(data))
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
