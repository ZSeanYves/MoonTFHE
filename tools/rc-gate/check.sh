#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 - "$root_dir" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
blockers = []
api = (root / "src/boolean/api.mbt").read_text()
interface = (root / "src/boolean/pkg.generated.mbti").read_text()
for name in ("boolean-110", "boolean-128"):
    output = json.loads((root / f"tools/parameter_estimator/outputs/{name}.json").read_text())
    if output["status"] != "verified":
        blockers.append(f"{name} estimator status is {output['status']}")
    if output.get("noise_model_status") != "verified_fixed_point_union_bound":
        blockers.append(f"{name} noise model is not verified")
    if output.get("failure_probability", {}).get("log2_upper_bound", 0) > -int(name[-3:]):
        blockers.append(f"{name} failure bound misses its target")
lock = (root / "tools/parameter_estimator/image.lock").read_text()
if "UNAVAILABLE_NO_CONTAINER_IMAGE" in lock:
    blockers.append("estimator OCI digest is not pinned")
published = json.loads((root / "tools/parameter-fixtures.json").read_text())
if published.get("estimator_status") != "verified":
    blockers.append("published parameter metadata is not estimator-verified")
for record in published.get("records", []):
    if record.get("reference_only") is not False:
        blockers.append(f"{record.get('id', 'parameter')} remains reference_only")
if "ServerKey::deserialize" not in interface:
    blockers.append("ServerKey::deserialize is unavailable")
for symbol in (
    "generate_keys",
    "ClientKey::encrypt",
    "ClientKey::decrypt",
    "ServerKey::apply_lut",
    "ServerKey::nand",
    "ServerKey::mux",
    "ClientKey::import_secret",
):
    if symbol not in interface:
        blockers.append(f"stable API symbol is missing: {symbol}")
stress = (root / "src/boolean/standard_stress_native_test.mbt").read_text()
for target in ("110", "128"):
    if f"standard {target}: 1000 random Boolean circuit steps" not in stress:
        blockers.append(f"{target}-bit 1000-step circuit test is missing")
benchmark = root / "docs/benchmarks-tfhe-rs.json"
if not benchmark.exists():
    blockers.append("tfhe-rs comparison benchmark is unavailable")
else:
    result = subprocess.run(
        [
            sys.executable,
            str(root / "tools/benchmark/check.py"),
            str(benchmark),
            "--require-rc-performance",
        ],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        blockers.append(f"benchmark evidence fails the RC gate: {result.stderr.strip()}")
    else:
        benchmark_data = json.loads(benchmark.read_text())
        evidence_commit = benchmark_data.get("repository_commit", "")
        if len(evidence_commit) != 40:
            blockers.append("benchmark evidence has no full repository commit")
        elif subprocess.run(
            ["git", "merge-base", "--is-ancestor", evidence_commit, "HEAD"],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode != 0:
            blockers.append("benchmark evidence commit is not an ancestor of HEAD")
if not (root / "tools/benchmark/tfhe-rs/Cargo.lock").exists():
    blockers.append("tfhe-rs benchmark dependency graph is not locked")
score_path = root / "docs/rc-score.json"
if not score_path.exists():
    blockers.append("RC weighted score evidence is unavailable")
else:
    score = json.loads(score_path.read_text())
    categories = score.get("categories", {})
    minimums = {
        "correctness": 31,
        "security": 21,
        "boolean_api": 14,
        "performance": 10,
        "tests_docs_maintenance": 9,
    }
    total = 0
    for category, minimum in minimums.items():
        value = categories.get(category)
        if not isinstance(value, int):
            blockers.append(f"RC score {category} is missing or non-integer")
            continue
        total += value
        if value < minimum:
            blockers.append(f"RC score {category} is below {minimum}")
    if score.get("total") != total or total < 85:
        blockers.append(f"RC total score is {total}, expected at least 85")
if blockers:
    print("RC gate blocked:")
    for blocker in blockers:
        print(f"- {blocker}")
    raise SystemExit(1)
print("RC gate passed")
PY
