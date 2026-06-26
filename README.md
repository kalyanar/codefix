# codefix

**Exploit-verified, transferable cross-function security repair with structural memory.**

codefix is the verified-repair-and-learning layer that sits above coding agents and
static scanners. It detects cross-function authorization defects (BOLA, BFLA, missing
authentication, SSRF, mass assignment) by call-graph taint + guard-dominance analysis,
repairs them from parameterized templates, **verifies every fix against a real exploit**
in a sandbox, and **remembers** what worked — keyed by a structure-invariant *facet
fingerprint* — so cost falls as the same defect recurs across codebases.

## Part of the paper

This repository is the research artifact accompanying:

> **Codefix: A Cross-Functional Repair-and-Learn Security Layer for AI Coding Agents**
> Gopal Kalyanaraman and Vijay K. Madisetti, Georgia Institute of Technology (IEEE, in submission).

It contains the running prototype, the benchmark harness, and the experiments behind the
paper's figures and tables (the all-baselines head-to-head, the F1 learning curve, the
transfer result, and the selection-regret ablation).

- **Project website (overview, architecture diagrams, results):**
  https://codefix-kalyanars-projects.vercel.app *(access-gated during review)*

## What's in here

```
src/codefix/
  graph.py        cross-file call graph + decorator + parameter-flow edges
  taint.py        def-use taint propagation to a fixpoint
  detect.py       5 OWASP detectors + DetectorSpec + guard-dominance check
  fingerprint.py  path-semantic facet fingerprint + embedding + precondition mask
  memory.py       SQLite PatchMemory: fingerprints, templates, outcomes, fuzzy recall
  propose.py      parameterized fix templates + candidate generation
  validate.py     four-stage validator: exploit · differential · contract · adversarial
  learn.py        greedy / Thompson selection on Beta posteriors (hierarchical prior)
  contrastive.py  feature-flagged contrastive embedding (learns facet relevance)
  triage.py       non-gating detector prioritization
  authoring.py    self-test-gated developer-extensible detector catalog
  providers.py    LLM cold path (mock + Anthropic)
  orchestrate.py  the observable Perceive→Detect→…→Learn loop
  pr.py           pull-request draft with exploit evidence
  cli.py          codefix CLI (scan-bench, transfer-demo, coldstart-demo, author-demo)

bench/
  apps/           in-process fixtures (5 classes, safe/unsafe + structural variants)
  apps/vampi/     vendored OWASP VAmPI + live HTTP exploit/legit reproducers
  apps/crapi/     vendored OWASP crAPI runner (10-container reference app)
  experiments.py  F1 / F2 / ablation figures
  baselines.py    Bandit / Semgrep / Pysa / CodeQL head-to-head
  repro/          pinned linux/amd64 Docker image + reproduce.sh

tests/test_slice.py   the 29 mechanism tests (all green)
```

## Run it

```bash
pip install -e ".[dev]"           # protobuf + pytest; the anthropic SDK is only needed for the real LLM cold path
python3 -m pytest                 # the full suite (29 tests); pythonpath=src is set in pyproject.toml

# CLI (no install needed):
PYTHONPATH=src python3 -m codefix.cli scan-bench --runs 3       # F1 data points
PYTHONPATH=src python3 -m codefix.cli transfer-demo             # learn on one codebase, reuse on another

# Live VAmPI (needs Docker + requests):
cd bench/apps/vampi && python3 run_vampi.py

# Paper figures / baselines:
python3 bench/experiments.py
python3 bench/baselines.py
```

Tests and demos use a **mock LLM**, so no API key is required. The real cold path uses
`ANTHROPIC_API_KEY`.

## Reproducibility

The full suite and all figures run from a pinned `linux/amd64` Docker image in
`bench/repro/`; on an `aarch64` host the x86-only baselines (Pysa, CodeQL) are run under
`qemu`/amd64 emulation. See `bench/repro/README.md`.

## Note on vendored applications

`bench/apps/vampi` and `bench/apps/pygoat` vendor third-party OWASP projects, used solely
as evaluation targets and retained under their original upstream licenses.
