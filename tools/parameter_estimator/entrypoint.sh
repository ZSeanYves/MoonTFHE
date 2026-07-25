#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: estimator INPUT_JSON" >&2
  exit 2
fi
exec sage -python /workspace/estimate.py "$1"
