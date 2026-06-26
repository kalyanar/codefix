# Reproducibility — runs anywhere

The aarch64-vs-x86_64 pain we hit (Pysa/CodeQL ship x86_64-only binaries) is
*exactly* why the evaluation is dockerized with a **pinned `linux/amd64`
platform**: the image runs natively on x86_64 and on arm64/aarch64 via qemu, so
the paper's results reproduce on any machine from one artifact.

## One command (core results)

```bash
docker build  --platform linux/amd64 -t codefix-repro -f bench/repro/Dockerfile .
docker run    --platform linux/amd64 --rm codefix-repro
```

Reproduces, in one image:
1. **codefix mechanism tests** — exploit-verified repair, cross-codebase + cross-
   structure transfer, up/down-chain dominance, def-use taint, the 4-stage
   validator, the authoring gate (the full slice test suite).
2. **F1/F2 corpus harness** — in-process apps, A/B partition, exploit-verified
   success + warm-start transfer metrics.
3. **SAST baselines** — Bandit + Semgrep over the corpus (0 cross-function authz;
   they *do* find single-function SQLi/secrets — complementary).
4. **Pysa baseline** — interprocedural taint; finds the injection flow, **not**
   the BOLA (BOLA isn't a taint-to-sink flow).

## On arm64/aarch64 hosts (one-time)

Enable amd64 emulation once, then the commands above just work:
```bash
docker run --privileged --rm tonistiigi/binfmt --install amd64
```
(We verified this on aarch64: Pysa and CodeQL — both x86_64-only — run fine under it.)

## Heavier stacks (separate, documented)

Kept out of the core image to keep it small; each is its own dockerized step:
- **CodeQL baseline** — `bench/baselines/RESULTS_pysa_codeql.md`. Mount the CodeQL
  bundle into an amd64 container; `database create` + `analyze`. (~773 MB bundle.)
- **VAmPI** (real Flask app, 2 exploit-verified BOLAs) — `bench/apps/vampi/run_vampi.py`.
- **crAPI** (real OWASP API app, order BOLA) — `bench/apps/crapi/run_crapi.py`
  (10-container compose).

## Why this satisfies the reviewers

"Reproducible from one artifact" was a stated requirement. The pinned-platform
image makes every *runnable* result (mechanism + F1/F2 + Bandit/Semgrep/Pysa)
reproduce identically regardless of host architecture; the real-app and CodeQL
stacks are one dockerized command each. No "works on my machine."
