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
  graph.py        CodeMap: three-pass cross-file call graph (functions, imports incl.
                  relative, resolved call edges), def-use + decorator edges, and a
                  per-function statement IR with a control-flow graph
  ir.py           language-neutral statement IR, CFG dominators, guard dominance
  scip.py         SCIP index decoding (stdlib) + symbol parsing
  scipgraph.py    SCIP-derived CallGraphProvider (TypeScript and other brace languages)
  taint.py        def-use taint (with source roles) and principal closures
  detect.py       the generic engine: DetectorSpec (sink matcher x missing guard x
                  search direction), Alg. 1 detection, Alg. 2 bounded mitigation walk
  fingerprint.py  path-semantic facet fingerprint + embedding + precondition mask
  templates.py    TemplateSpec + render_patch: fixes rendered from the target's own AST
  memory.py       PatchMemory: eight FK-linked SQLite tables, posteriors, fuzzy recall
  propose.py      candidate generation (templates, fuzzy recall, LLM cold path)
  validate.py     four-stage validator: exploit · differential · contract · adversarial
  learn.py        greedy / Thompson selection on shared Beta posteriors
  contrastive.py  feature-flagged contrastive embedding
  triage.py       non-gating detector prioritization
  authoring.py    self-test-gated developer-extensible catalog
  providers.py    LLM cold path (mock + Anthropic)
  orchestrate.py  the observable Perceive -> ... -> Learn loop
  pr.py           pull-request draft with the executed-stage evidence and applied diff
  cli.py          codefix scan (+ scan-bench, transfer-demo, coldstart-demo, author-demo)

bench/
  apps/               fixtures: five classes with safe twins, structural variants,
                      a three-module package, a TypeScript/SCIP app
  apps/vampi/         vendored OWASP VAmPI + live before/after harness
  apps/crapi/         vendored crAPI workshop service + live before/after harness
  live_codefix.py     codefix's own fixes on live VAmPI / crAPI
  live_results/       verdicts and PR drafts from those runs
  experiments.py      F1 / F2 / selection ablation / fuzzy / triage / contrastive / build time
  baselines.py        Bandit / Semgrep / Pysa / CodeQL head-to-head
  repro/              pinned linux/amd64 Docker image + reproduce.sh

tests/                mechanism tests (python3 -m pytest)
CLAIMS.md             every paper and site claim, and the code / test / run that backs it
```

## Run it

```bash
python3 -m pytest                          # no runtime dependencies; pytest only
CODEFIX_LIVE=1 python3 -m pytest -k live   # + live VAmPI / crAPI (Docker)

PYTHONPATH=src python3 -m codefix.cli scan bench/apps/shop_multifile --detect-only
PYTHONPATH=src python3 -m codefix.cli scan bench/apps/shop_multifile --dry-run
PYTHONPATH=src python3 -m codefix.cli scan bench/apps/shop_multifile --db /tmp/cf.db --pr /tmp/pr
PYTHONPATH=src python3 -m codefix.cli transfer-demo

python3 bench/live_codefix.py vampi        # Docker; codefix patch served on :5001
python3 bench/live_codefix.py crapi        # Docker; codefix-patched workshop swapped in
python3 bench/experiments.py
python3 bench/baselines.py
```

Tests and demos use a **mock LLM**, so no API key is required. The real cold path uses
`ANTHROPIC_API_KEY` (`--provider anthropic`).

## Reproducibility

The full suite and all figures run from a pinned `linux/amd64` Docker image in
`bench/repro/`; on an `aarch64` host the x86-only baselines (Pysa, CodeQL) are run under
`qemu`/amd64 emulation. See `bench/repro/README.md`.

## Note on vendored applications

`bench/apps/vampi`, `bench/apps/crapi/vendor` and `bench/apps/pygoat` vendor third-party OWASP projects, used solely
as evaluation targets and retained under their original upstream licenses.
