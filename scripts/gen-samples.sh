#!/usr/bin/env bash
# Generates synthetic sample data for performance and boundary checks.
#
#   scripts/gen-samples.sh                     # 1000 records to stdout
#   scripts/gen-samples.sh --records 100000 --out /tmp/big.json
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec go run ./scripts/bfptool gen "$@"
