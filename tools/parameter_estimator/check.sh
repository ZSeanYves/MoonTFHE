#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 - "$root_dir" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
base = root / "tools/parameter_estimator"
commit = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
lock_values = {}
for line in (base / "image.lock").read_text().splitlines():
    if ": " in line:
        key, value = line.split(": ", 1)
        lock_values[key] = value
for key in ("digest", "base_digest"):
    value = lock_values.get(key, "")
    assert value.startswith("sha256:") and len(value) == len("sha256:") + 64, (
        f"{key} is not an immutable digest"
    )

metadata = json.loads((root / "tools/noise_fixtures/standard-cdt.json").read_text())
fixture_by_name = {item["name"]: item for item in metadata["fixtures"]}
fixture_names = {
    "boolean-110": ("boolean_110_lwe", "boolean_110_glwe"),
    "boolean-128": ("boolean_128_lwe", "boolean_128_glwe"),
}
published = json.loads((root / "tools/parameter-fixtures.json").read_text())
assert published["estimator_status"] == "verified"
published_by_target = {
    item["target_security_bits"]: item for item in published["records"]
}
for name in ("boolean-110", "boolean-128"):
    inp = json.loads((base / "inputs" / f"{name}.json").read_text())
    out = json.loads((base / "outputs" / f"{name}.json").read_text())
    assert inp["estimator_commit"] == commit
    assert out["estimator_commit"] == commit
    assert inp["target_security_bits"] in (110, 128)
    assert inp["modulus"] == "2^32"
    assert inp["secret_distribution"] == "binary"
    assert inp["pbs_order"] == "bootstrap_keyswitch"
    assert inp["fft_mantissa_bits"] == 53
    assert inp["boolean_encoding"]["pre_pbs_margin_log2"] == -4
    assert inp["boolean_encoding"]["decrypt_margin_log2"] == -3
    assert inp["pbs_decomposition"]["base_log"] * inp["pbs_decomposition"]["level"] <= 32
    assert inp["ks_decomposition"]["base_log"] * inp["ks_decomposition"]["level"] <= 32
    for noise, fixture_name in zip(
        (inp["lwe_noise"], inp["glwe_noise"]), fixture_names[name]
    ):
        fixture = fixture_by_name[fixture_name]
        assert noise["distribution"] == "discrete_gaussian_cdt_u192"
        assert noise["sigma_scale_bits"] == 32
        assert noise["tail_sigma"] == metadata["tail_sigma"] == 16
        assert noise["threshold_bits"] == 192
        assert noise["entries"] == fixture["entries"]
        assert noise["tail_bound"] == fixture["tail_bound"]
        assert noise["fixture_hash"] == fixture["table_hash"]
        assert noise["single_sample_tv_log2_upper"] == fixture["single_sample_tv_log2_upper"]
    assert out["parameter_id"] == inp["parameter_id"]
    canonical = json.dumps(inp, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    assert out["input_sha256"] != "pending"
    assert out["input_sha256"] == digest
    assert out["status"] == "verified"
    assert isinstance(out["security_bits"], (int, float))
    assert out["security_bits"] >= inp["target_security_bits"]
    assert out["noise_model_status"] == "verified_fixed_point_union_bound"
    assert out["failure_probability"]["union_bound"] is True
    assert out["failure_probability"]["log2_upper_bound"] <= -inp["target_security_bits"]
    assert out["noise_model_source"]["tfhe_rs_commit"] == "640911eba7a394f078fa5d7d14e146105757e34f"
    assert out["noise_margin"]["pre_pbs_sigma_scale"] > 1.0
    assert out["noise_margin"]["decrypt_sigma_scale"] > 1.0
    record = published_by_target[inp["target_security_bits"]]
    assert record["reference_only"] is False
    assert abs(
        record["failure_exponent_log2"]
        - round(out["failure_probability"]["log2_upper_bound"], 3)
    ) < 0.001
print("parameter estimator schema, fixtures, hashes, and noise bounds verified")
PY
