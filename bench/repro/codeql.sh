#!/usr/bin/env bash
# CodeQL baseline in one dockerized command (pinned linux/amd64):
# CodeQL CLI 2.27.0 + codeql/python-queries 1.8.10, `python-security-extended.qls`
# plus the hand-written BarrierGuard BOLA query, over every corpus target.
# Raw SARIF lands in bench/baselines/raw/codeql/linux-x86_64/; then run
# `python bench/baselines.py report`.
#
# On an aarch64 host, register qemu amd64 emulation first (lost at reboot):
#   docker run --privileged --rm tonistiigi/binfmt --install amd64
set -euo pipefail
cd "$(dirname "$0")/../.."

note="linux/amd64 container"
[ "$(uname -m)" != "x86_64" ] && note="linux/amd64 container under qemu-user, host arch $(uname -m)"

docker build --platform linux/amd64 --build-context apps=bench/apps -t codefix-codeql -f bench/repro/Dockerfile.codeql .
docker run --platform linux/amd64 --rm \
    --user "$(id -u):$(id -g)" -e HOME=/tmp -e CODEFIX_HOST_NOTE="$note" \
    -v "$PWD/bench/baselines/raw:/codefix/bench/baselines/raw" \
    codefix-codeql "$@"
