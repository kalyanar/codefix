# Reproducibility image — pinned to linux/amd64 so it runs ANYWHERE:
# native on x86_64, and on arm64/aarch64 via qemu (docker --platform handles it).
# This is the "reproducible from one artifact" the paper's evaluation needs.
#
#   docker build --platform linux/amd64 -t codefix-repro -f bench/repro/Dockerfile .
#   docker run  --platform linux/amd64 --rm codefix-repro
#
# Reproduces: codefix mechanism tests, the SAST baselines (Bandit, Semgrep, Pysa),
# and the in-process F1/F2 corpus run. (CodeQL + the dockerized real apps
# VAmPI/crAPI are separate heavier stacks — see bench/repro/README.md.)
FROM --platform=linux/amd64 python:3.11-slim

RUN pip install --no-cache-dir pytest bandit semgrep pyre-check

WORKDIR /codefix
COPY . /codefix
ENV PYTHONPATH=/codefix/src

ENTRYPOINT ["bash", "/codefix/bench/repro/reproduce.sh"]
