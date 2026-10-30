#!/bin/sh
set -eu

cd -- "$(dirname -- "$0")/.."

# The approved root configuration selects contracts/test. Keep it intact and run
# both that accepted suite and the contribution in test through process-local settings.
export FOUNDRY_FUZZ_SEED=0x80e5d2ec1a22300e4a3b356a910d5e0498d6fef211dbe8ed7b21918d50efa1d6
export FOUNDRY_OUT=test/scratch/check-out
export FOUNDRY_CACHE_PATH=test/scratch/check-cache

FOUNDRY_TEST=contracts/test forge build --offline
FOUNDRY_TEST=contracts/test forge test --offline "$@"
FOUNDRY_TEST=test forge build --offline
FOUNDRY_TEST=test forge test --offline --no-match-path 'test/scratch/**' "$@"
