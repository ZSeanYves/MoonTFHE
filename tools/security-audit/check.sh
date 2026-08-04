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

python3 - <<'PY'
import re
from pathlib import Path


def production_source(path: Path) -> str:
    """Remove MoonBit test blocks before checking production control flow."""
    lines = path.read_text().splitlines()
    output = []
    skipping = False
    depth = 0
    for line in lines:
        if not skipping and re.match(r"\s*test(?:\s+|\s*\()", line):
            skipping = True
            depth = line.count("{") - line.count("}")
            continue
        if skipping:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                skipping = False
            continue
        output.append(line)
    return "\n".join(output)


production_roots = "src/boolean src/core src/params src/polynomial src/random src/torus".split()
sources = "\n".join(
    production_source(path)
    for root in production_roots
    for path in Path(root).rglob("*.mbt")
    if not path.name.endswith(("_test.mbt", "_wbtest.mbt"))
)
for pattern, description in (
    (r"\babort\s*\(", "abort found in production control flow"),
    (r"\bpanic\s*\(", "panic found in production control flow"),
    (r"\.unwrap\s*\(", "unwrap found in production control flow"),
    (r"SystemTime|Instant::now|Date\.now|time_seed", "time-derived seed found in production"),
):
    if re.search(pattern, sources):
        raise SystemExit(description)

if re.search(r"cdt_chunk_from_hex|from_hex", sources):
    raise SystemExit("runtime CDT parsing found; fixtures must be integer literals")


def struct_body(text: str, name: str) -> str:
    match = re.search(rf"pub struct {name} \{{(?P<body>.*?)\n\}}", text, re.S)
    if match is None:
        raise AssertionError(f"missing {name} in generated interface")
    return match.group("body")


boolean_interface = Path("src/boolean/pkg.generated.mbti").read_text()
for type_name, text in (("ServerKey", boolean_interface),):
    body = struct_body(text, type_name).lower()
    for forbidden in ("secret", "lwe_key", "trlwe_key", "s_bits"):
        assert forbidden not in body, f"{type_name} exposes {forbidden}"

client_block = struct_body(boolean_interface, "ClientKey")
assert "ClientKey::serialize" not in boolean_interface
assert "ClientKey::export_secret" in boolean_interface
assert "lwe_key" not in client_block.lower()
print("security boundary checks passed")
PY
