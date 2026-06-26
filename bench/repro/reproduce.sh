#!/usr/bin/env bash
# One-command reproduction of codefix's runnable results. Invoked by the repro
# Docker image (pinned linux/amd64), so it produces identical results on any host.
set -uo pipefail
cd /codefix

line() { printf '\n=== %s ===\n' "$1"; }

line "1. codefix mechanism tests (exploit-verified repair, transfer, dominance, taint, authoring gate)"
python -m pytest -q tests/ 2>&1 | tail -3

line "2. F1/F2 corpus harness (in-process apps; A/B partition)"
python bench/harness.py 2>&1 | tail -7

line "3. SAST baselines — Bandit + Semgrep (0 cross-function authz vs codefix)"
python bench/baselines.py 2>&1 | tail -8

line "4. Pysa baseline — interprocedural taint (finds the injection flow, NOT the BOLA)"
cd bench/baselines/pysa_ws
TS=$(find / -path '*/pyre_check/typeshed/stdlib' -type d 2>/dev/null | head -1 | xargs dirname)
printf '{"source_directories":["."],"taint_models_path":["."],"typeshed":"%s"}' "$TS" > .pyre_configuration
pyre --noninteractive analyze 2>&1 | grep -E "Found .* issue|code execution|get_order" | tail -5
cd /codefix

line "DONE — all results above reproduced from one image"
