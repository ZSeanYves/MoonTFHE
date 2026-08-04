#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
fixture="$root_dir/docs/fixtures/tfhe-rs-boolean-oracle.json"

python3 - "$fixture" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
assert data["format"] == "moontfhe-r0-boolean-oracle-v1"
assert data["upstream"]["commit"] == "640911eba7a394f078fa5d7d14e146105757e34f"
assert data["status"] == "scalar-contract-only"
assert data["signed_decomposition"]["digit_order"] == "largest-gadget-weight-first"
assert len(data["signed_decomposition"]["vectors"]) >= 6
assert data["sample_extraction"]["lwe_mask"] == [1, -4, -3, -2]
assert data["sample_extraction"]["body"] == 10
assert data["pbs_orders"] == ["bootstrap-keyswitch", "keyswitch-bootstrap"]
assert data["torus32"] == {"true": 536870912, "false": -536870912, "modulus": "2^32"}
vectors = data["signed_decomposition"]["vectors"]
assert [item["raw"] for item in vectors] == [
    "0x00000000", "0x00000001", "0x7fffffff", "0x80000000",
    "0xffffffff", "0x12345678",
]
assert vectors[-1]["digits"] == [1, -3, -4, 3, 2]
print("Boolean scalar oracle fixture is canonical")
PY
