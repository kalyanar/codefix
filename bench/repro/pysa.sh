#!/usr/bin/env bash
# Bandit, Semgrep and Pysa over the corpus inside the pinned linux/amd64 repro image.
# Raw output lands in bench/baselines/raw/<tool>/linux-x86_64/; then run
# `python bench/baselines.py report`.
#
# On an aarch64 host, register qemu amd64 emulation first (lost at reboot):
#   docker run --privileged --rm tonistiigi/binfmt --install amd64
set -euo pipefail
cd "$(dirname "$0")/../.."

note="linux/amd64 container"
[ "$(uname -m)" != "x86_64" ] && note="linux/amd64 container under qemu-user, host arch $(uname -m)"

docker build --platform linux/amd64 --build-context apps=bench/apps -t codefix-repro -f bench/repro/Dockerfile .
# Runs as root: pyre's server calls getlogin(), which fails for a --user uid that has
# no passwd entry. Ownership of the written raw output is handed back afterwards.
docker run --platform linux/amd64 --rm \
    -e CODEFIX_HOST_NOTE="$note" -e TOOLS="${TOOLS:-bandit,semgrep,pysa}" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$PWD/bench/baselines/raw:/codefix/bench/baselines/raw" \
    --entrypoint bash codefix-repro -c '
        python bench/baselines.py run --tools "$TOOLS" --strict "$@"; rc=$?
        chown -R "$HOST_UID:$HOST_GID" bench/baselines/raw
        exit $rc' _ "$@"
