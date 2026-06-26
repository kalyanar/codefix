# M5 baselines — Bandit + Semgrep vs codefix

External SAST tools (Bandit 1.9.4, Semgrep 1.166.0, default rulesets) run over the
corpus, tallying **cross-function authorization defects (BOLA/BFLA)** — the class
codefix targets. Reproduce with `python bench/baselines.py`.

## Result: file-local SAST finds 0 cross-function authz; codefix finds them

| Target | Bandit total | Semgrep total | BOLA/BFLA (baseline) | BOLA/BFLA (codefix) |
|---|---:|---:|---:|---:|
| VAmPI (whole repo) | 7 | 4 | **0** | BOLA (exploit-verified*) |
| shop_bola | 0 | 0 | **0** | **1 (BOLA)** |
| admin_bfla | 0 | 0 | **0** | **1 (BFLA)** |

\* VAmPI's BOLA is exploit-verified behaviorally (`run_vampi.py`); static detection
on real multi-file apps is M4-proper (the slice detector is single-module).

## What Bandit/Semgrep *did* find on VAmPI (complementary, not competing)

- **Bandit (7):** 4× hardcoded password (B105), 1× bind-all-interfaces (B104),
  **1× SQL injection (B608)**, 1× weak randomness (B311).
- **Semgrep (4):** JWT-token usage, hardcoded SECRET_KEY, missing-user-entrypoint.

These are **single-function / config** defects — exactly the class file-local
matchers are good at, and exactly what codefix deliberately does *not* target.
Bandit correctly finds VAmPI's SQLi (string-concat into a query, one function);
codefix doesn't target SQLi. Neither tool flags the books BOLA — there is no
syntactic anomaly in `get_by_title`; the defect is the *absence* of an ownership
check on the call path, which a file-local rule cannot express.

## Takeaway for the paper

This is the reviewer-demanded head-to-head, and it lands as the architecture
predicts: **codefix and SAST are complementary.** Bandit/Semgrep own
single-function defects (SQLi, secrets, weak crypto); codefix owns the
cross-function authorization class they structurally miss. Position codefix as the
layer *above* these tools, not a competitor — and use them as finding sources for
the classes they do cover.

## M5 status

- **Done:** Bandit + Semgrep adapters, run over the corpus, comparison table.
- **Pending:** CodeQL (with authorization queries; needs the CLI + per-app DB
  build) and Pysa/pyre (Python taint; needs taint-model config). Both are heavier
  installs; the v1 repo already has a `RESULTS_pysa.md` data point to reproduce.
  CodeQL is the important one — it *can* express the guard-dominance shape via
  `BarrierGuard`, so it's the strongest baseline; expect it to need hand-authored
  authorization queries (no built-in ownership), which is itself a finding.
