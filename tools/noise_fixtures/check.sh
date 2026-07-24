#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
fixture="$root_dir/tools/noise_fixtures/sigma-3-cdt.json"
expected="1839de5e5990ccec2baa162916d353175ea9a93e3ed94dff6dc639e65952a784"

actual=$(sha256sum "$fixture" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  echo "noise fixture hash mismatch: expected $expected, got $actual" >&2
  exit 1
fi

echo "noise fixture verified: $actual"
