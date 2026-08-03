#!/bin/sh
set -eu

if [ "${MOONTFHE_FFT_ALLOCATION_COUNTER:-0}" = "1" ]; then
  cargo build --manifest-path native/fft/Cargo.toml --release --locked \
    --features allocation-counter
else
  cargo build --manifest-path native/fft/Cargo.toml --release --locked
fi
cargo build --manifest-path native/aead/Cargo.toml --release --locked
