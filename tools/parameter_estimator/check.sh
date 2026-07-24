#!/bin/sh
set -eu

python3 - <<'PY'
import json
from pathlib import Path

path = Path("tools/parameter-fixtures.json")
data = json.loads(path.read_text())
assert data["estimator_status"] == "metadata-only"
assert data["source"]["commit"] == "640911eba7a394f078fa5d7d14e146105757e34f"
records = data["records"]
assert {record["target_security_bits"] for record in records} == {110, 128}
for record in records:
    assert record["reference_only"] is True
    assert record["upstream_security_bits"] >= record["target_security_bits"]
    assert record["failure_exponent_log2"] < 0
    assert record["polynomial_size"] & (record["polynomial_size"] - 1) == 0
    assert record["pbs_base_log"] * record["pbs_level"] <= 32
    assert record["ks_base_log"] * record["ks_level"] <= 32
print("parameter fixture metadata checks passed; cryptanalytic estimator is not yet vendored")
PY
