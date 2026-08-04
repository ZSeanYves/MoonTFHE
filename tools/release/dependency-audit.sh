#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root_dir"

echo "Rust dependency graph:"
cargo metadata --locked --format-version 1 --no-deps \
  --manifest-path native/fft/Cargo.toml >/tmp/moontfhe-fft-metadata.json
cargo metadata --locked --format-version 1 --no-deps \
  --manifest-path native/aead/Cargo.toml >/tmp/moontfhe-aead-metadata.json
printf '%s\n' "native/fft and native/aead metadata generated in /tmp"

if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit --locked --manifest-path native/fft/Cargo.toml
  cargo audit --locked --manifest-path native/aead/Cargo.toml
else
  printf '%s\n' "cargo-audit unavailable; CI release jobs must install it before publication" >&2
fi

if command -v syft >/dev/null 2>&1; then
  syft dir:"$root_dir" -o spdx-json=/tmp/moontfhe-sbom.spdx.json
  printf '%s\n' "SBOM generated at /tmp/moontfhe-sbom.spdx.json"
else
  printf '%s\n' "syft unavailable; CI release jobs must install it before publication" >&2
fi
