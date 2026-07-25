#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 - "$root_dir" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
blockers = []
api = (root / "src/boolean/api.mbt").read_text()
interface = (root / "src/boolean/pkg.generated.mbti").read_text()
if "Err(UnsupportedBackend)" in api[api.index("pub fn generate_keys"):api.index("pub fn generate_test_keys")]:
    blockers.append("standard generate_keys is unavailable")
for name in ("boolean-110", "boolean-128"):
    output = json.loads((root / f"tools/parameter_estimator/outputs/{name}.json").read_text())
    if output["status"] != "verified":
        blockers.append(f"{name} estimator status is {output['status']}")
lock = (root / "tools/parameter_estimator/image.lock").read_text()
if "UNAVAILABLE_NO_CONTAINER_IMAGE" in lock:
    blockers.append("estimator OCI digest is not pinned")
if "ServerKey::deserialize" not in interface:
    blockers.append("ServerKey::deserialize is unavailable")
if not (root / "docs/benchmarks-tfhe-rs.json").exists():
    blockers.append("tfhe-rs comparison benchmark is unavailable")
if blockers:
    print("RC gate blocked:")
    for blocker in blockers:
        print(f"- {blocker}")
    raise SystemExit(1)
print("RC gate passed")
PY
