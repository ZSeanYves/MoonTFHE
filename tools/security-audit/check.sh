#!/bin/sh
set -eu

production_paths="src/boolean src/core src/params src/polynomial src/random src/torus"

if rg -n 'SplitMix64|sample_discrete_gaussian_0sigma|Box[- ]Muller|central limit|CLT' \
  $production_paths --glob '*.mbt' --glob '!**/*_test.mbt'; then
  echo "forbidden legacy randomness or noise sampler found in production packages" >&2
  exit 1
fi

if rg -n 'Gaussian\(Double\)|sample_discrete_gaussian\(' \
  $production_paths --glob '*.mbt' --glob '!**/*_test.mbt'; then
  echo "floating-point Gaussian API found in a maintained production package" >&2
  exit 1
fi

if rg -n 'panic\(' $production_paths --glob '*.mbt' --glob '!**/*_test.mbt'; then
  echo "panic found in a maintained production package" >&2
  exit 1
fi

python3 - <<'PY'
import re
from pathlib import Path


def struct_body(text: str, name: str) -> str:
    match = re.search(rf"pub struct {name} \{{(?P<body>.*?)\n\}}", text, re.S)
    if match is None:
        raise AssertionError(f"missing {name} in generated interface")
    return match.group("body")


root_interface = Path("src/pkg.generated.mbti").read_text()
boolean_interface = Path("src/boolean/pkg.generated.mbti").read_text()
for type_name, text in (
    ("BootstrappingKey", root_interface),
    ("ServerKey", boolean_interface),
):
    body = struct_body(text, type_name).lower()
    for forbidden in ("secret", "lwe_key", "trlwe_key", "s_bits"):
        assert forbidden not in body, f"{type_name} exposes {forbidden}"

client_block = struct_body(boolean_interface, "ClientKey")
assert "ClientKey::serialize" not in boolean_interface
assert "ClientKey::export_secret" in boolean_interface
assert "ServerKey::deserialize" not in boolean_interface
assert "lwe_key" not in client_block.lower()
print("security boundary checks passed")
PY
