# Reproducibility

Pysa's analysis binary (`pyre.bin`) ships for x86-64 only, so the evaluation
images are pinned to `linux/amd64`. They run natively on x86_64 and on
arm64/aarch64 through qemu-user.

## On arm64/aarch64 hosts

Register amd64 emulation (privileged, not persistent across reboots):
```bash
docker run --privileged --rm tonistiigi/binfmt --install amd64
```

## Commands

| Command | What it runs | Output |
|---|---|---|
| `bench/repro/pysa.sh` | Bandit 1.9.4, Semgrep 1.166.0, Pysa (pyre-check 0.9.25) over the corpus, in the `codefix-repro` image | `bench/baselines/raw/{bandit,semgrep,pysa}/linux-x86_64/` |
| `bench/repro/codeql.sh` | CodeQL CLI 2.27.0 + python-queries 1.8.10: `python-security-extended.qls` and `bench/baselines/codeql/BolaBarrierGuard.ql`, in the `codefix-codeql` image | `bench/baselines/raw/codeql/linux-x86_64/` |
| `python bench/baselines.py report` | classifies the saved raw output (no tools needed) | `bench/RESULTS_baselines.md`, `bench/baselines/RESULTS_pysa_codeql.md`, `bench/baseline_results.json` |
| `docker run --platform linux/amd64 --rm codefix-repro` | test suite, corpus harness, then Bandit/Semgrep/Pysa and the report, inside the container | stdout |

Both images take the vendored real apps from a named build context
(`--build-context apps=bench/apps`), because the root `.dockerignore` drops
every `vendor/` directory. The scripts pass it; by hand:
```bash
docker build --platform linux/amd64 --build-context apps=bench/apps -t codefix-repro -f bench/repro/Dockerfile .
```

CodeQL also runs natively on arm64 (CodeQL 2.27.0 ships a `linux-arm64` build):
```bash
CODEQL=/path/to/codeql/codeql CODEQL_PACKS=/path/to/packs python bench/baselines.py run --tools codeql
```
The report compares native and amd64 raw output finding by finding.

## Other stacks

- VAmPI (real Flask app, two exploit-verified BOLAs): `bench/apps/vampi/run_vampi.py`.
- crAPI (real OWASP API app, shop-order BOLA): `bench/apps/crapi/run_crapi.py` (10-container compose).
