#!/usr/bin/env bash
# One-command reproduction of codefix's runnable results. Invoked by the repro
# Docker image (pinned linux/amd64), so it produces the same results on any host.
set -uo pipefail
cd /codefix

line() { printf '\n=== %s ===\n' "$1"; }

line "1. codefix mechanism tests"
python -m pytest -q tests/ 2>&1 | tail -3

line "2. F1/F2 corpus harness (in-process apps; A/B partition)"
python bench/harness.py 2>&1 | tail -7

line "3. SAST baselines: Bandit, Semgrep, Pysa over the corpus (raw output -> classifier)"
# Pysa runs on every corpus target with its shipped models, plus the toy workspace
# bench/baselines/pysa_ws with its hand-written models. CodeQL: bench/repro/codeql.sh.
python bench/baselines.py run --tools bandit,semgrep,pysa --strict
python bench/baselines.py report > /dev/null
sed -n '/^## Corpus totals/,/^## Native classes/p' bench/RESULTS_baselines.md
sed -n '/^## Paper Table III/,/^## Reproduce/p' bench/RESULTS_baselines.md
sed -n '/^## Pysa/,$p' bench/baselines/RESULTS_pysa_codeql.md

line "DONE"
