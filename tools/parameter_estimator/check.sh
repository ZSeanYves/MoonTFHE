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
for name in ("boolean-110", "boolean-128"):
    inp = json.loads((base / "inputs" / f"{name}.json").read_text())
    out = json.loads((base / "outputs" / f"{name}.json").read_text())
    assert inp["estimator_commit"] == commit
    assert out["estimator_commit"] == commit
    assert inp["modulus"] == "2^32"
    assert inp["secret_distribution"] == "binary"
    assert inp["pbs_decomposition"]["base_log"] * inp["pbs_decomposition"]["level"] <= 32
    assert inp["ks_decomposition"]["base_log"] * inp["ks_decomposition"]["level"] <= 32
    assert out["parameter_id"] == inp["parameter_id"]
    canonical = json.dumps(inp, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    if out["input_sha256"] == "pending":
        raise AssertionError(f"{name}: output input_sha256 is pending; run the locked estimator")
    assert out["input_sha256"] == digest
    if out["status"] == "not_run":
        assert out["security_bits"] is None
        assert out["failure_probability"] is None
        assert out["noise_margin"] is None
    else:
        assert out["status"] == "verified"
        assert isinstance(out["security_bits"], (int, float))
print("parameter estimator schema and hashes verified")
PY
