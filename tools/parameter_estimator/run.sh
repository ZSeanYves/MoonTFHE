#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [ "${1:-}" = "--check" ]; then
  exec sh "$root_dir/tools/parameter_estimator/check.sh"
fi

lock="$root_dir/tools/parameter_estimator/image.lock"
digest=$(awk '$1 == "digest:" {print $2}' "$lock")
if [ "$digest" = "sha256:UNAVAILABLE_NO_CONTAINER_IMAGE" ]; then
  echo "estimator image digest is not pinned; refusing cryptanalytic execution" >&2
  exit 2
fi
echo "build the locked OCI image with digest $digest before running estimator" >&2
exit 2
