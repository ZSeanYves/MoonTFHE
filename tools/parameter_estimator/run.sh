#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [ "${1:-}" = "--check" ]; then
  exec sh "$root_dir/tools/parameter_estimator/check.sh"
fi

lock="$root_dir/tools/parameter_estimator/image.lock"
image=$(awk '$1 == "image:" {print $2}' "$lock")
digest=$(awk '$1 == "digest:" {print $2}' "$lock")
case "$digest" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "estimator image digest is not pinned" >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "no container runtime; only schema/hash validation is available locally" >&2
  exec sh "$root_dir/tools/parameter_estimator/check.sh"
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/moontfhe-estimator.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
for name in boolean-110 boolean-128; do
  docker run --rm --platform linux/amd64 \
    "$image@$digest" \
    "/inputs/${name}.json" >"$tmp_dir/${name}.json"
done

python3 - "$root_dir" "$tmp_dir" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
generated = Path(sys.argv[2])
base = root / "tools/parameter_estimator"
for name in ("boolean-110", "boolean-128"):
    expected = json.loads((base / "outputs" / f"{name}.json").read_text())
    actual = json.loads((generated / f"{name}.json").read_text())
    if expected != actual:
        raise SystemExit(f"{name}: locked estimator output differs from committed fixture")
print("locked estimator outputs match committed fixtures")
PY
