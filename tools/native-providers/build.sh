#!/bin/sh
set -eu

cargo build --manifest-path native/fft/Cargo.toml --release --locked
cargo build --manifest-path native/aead/Cargo.toml --release --locked
