# M5 — Pysa & CodeQL baselines (the interprocedural / guard-expressive tools)

Bandit + Semgrep (file-local) already established 0 cross-function authz findings
(`bench/RESULTS_baselines.md`). Pysa and CodeQL are the *stronger* baselines:
Pysa does global interprocedural taint; CodeQL can express guard dominance
(`BarrierGuard`). The point of running them is to show that **even these find 0
BOLA out-of-box** — because BOLA is the *absence of an authorization check*, not a
taint-to-dangerous-sink flow, and authorization is application-specific.

## Pysa (Meta) — interprocedural Python taint

**RAN (via amd64 emulation).** The aarch64 host can't run the x86_64 `pyre.bin`
directly, so we registered qemu binfmt (`docker run --privileged tonistiigi/binfmt
--install amd64`) and ran Pysa inside a `--platform linux/amd64` Python container.

**Result — Pysa found the taint flow, NOT the BOLA:**
```
Found 1 issue:
  code 5001 "User input to code execution"
  target.search_handler  ->  run_query/eval   (interprocedural source->sink)
```
`target.get_order` (the BOLA — reads any record by id with no ownership check)
WAS analyzed (it appears in Pysa's callable set) but was **not flagged** — there is
no dangerous sink, so a real interprocedural taint engine has nothing to report.
This is the definitive baseline result, run live (not just argued).

**Why Pysa misses BOLA.** Pysa models **taint flows**
(source → sink) via `.pysa` models and a `taint.config`. It detects, e.g.,
user-input → `eval`/SQL/`subprocess`. It does **not** detect BOLA without
hand-authored models, because:
- BOLA has **no dangerous sink** — reading your own vs. another user's order is
  the *same* DB read; the defect is a *missing ownership comparison*, not a flow
  into a sink Pysa recognizes.
- Encoding "an authorization check must dominate this read" as a Pysa model is
  application-specific and effectively re-implements codefix's analysis.

The v1 repo's `RESULTS_pysa.md` corroborates: Pysa flags the injection-class flows
in the targets, not the cross-function authorization defects.

**Adapter status.** A minimal Pysa workspace (`bench/baselines/pysa_ws/`:
`target.py` with an injection flow + a BOLA, `taint.config`, `models.pysa`,
`.pyre_configuration`) is scaffolded and config-correct; it blocks only on the
wrong-arch binary. Runs as-is on an x86_64 host or with a native-arm pyre.

## CodeQL — the strongest baseline (BarrierGuard)

CodeQL is the one tool that *can* express our guard-dominance shape: its global
dataflow library + `BarrierGuard` (a node that, when it dominates a flow, blocks
taint).

**RAN (via amd64 emulation).** GitHub ships CodeQL only for x86_64 Linux (no
aarch64 build), so on this aarch64 host we ran it inside a `--platform linux/amd64`
container (qemu binfmt). `database create` (Python extractor) + `database analyze`
with `python-security-extended.qls` both completed under emulation.

**Result on VAmPI — CodeQL found single-function issues, 0 cross-function authz:**
```
total: 3
  py/polynomial-redos   2     (regex DoS — single function)
  py/redos              1     (regex DoS — single function)
  BOLA / BFLA           0
```
CodeQL flagged regex-DoS defects but **0** of VAmPI's authorization defects (the
books BOLA, the password-takeover BOLA) — its standard suite has no authorization
query.

**Expected/known finding** (standard `python-security-and-quality` suite):
- finds single-function issues (injection, hardcoded secrets, unsafe deserialize);
- finds **0 BOLA/BFLA**, because the standard suite has **no authorization
  query** — authorization is application-specific (no built-in notion of "owner").

**The nuance that matters for the paper.** CodeQL *could* find BOLA — but only with
a **hand-authored authorization query** defining what "owner"/"principal" means
and using `BarrierGuard` for the ownership check. That codefix does this
**name-independently and learns/repairs** is the delta; that CodeQL needs a
bespoke per-app query (and no fix, no memory) is the gap. The "0 out-of-box" is
not a knock on CodeQL — it's evidence that **cross-function authorization is not
expressible by generic rules**, which is the paper's motivating point.

**Adapter status.** Env-blocked on this aarch64 host (no native CodeQL binary).
Adapter design: build a CodeQL DB per target (`codeql database create`), run the
`python-security-and-quality` suite (`codeql database analyze`), parse SARIF,
count findings + BOLA/BFLA(=0). Runs on an x86_64 host.

## Summary — M5 in this environment

| Tool | Kind | Ran here? | What it found | Cross-function authz |
|---|---|---|---|---|
| Bandit | file-local AST | ✓ native | SQLi (B608), hardcoded pw, weak random | **0** |
| Semgrep | pattern/taint | ✓ native | jwt, hardcoded secret, missing-user | **0** |
| Pysa | interproc taint | ✓ amd64 emul | the injection flow (argv→eval, code 5001) | **0** |
| CodeQL | dataflow + BarrierGuard | ✓ amd64 emul | regex DoS (py/redos ×3) on VAmPI | **0** |

**All four ran, and the result is unanimous**: file-local, interprocedural-taint,
AND guard-expressive SAST each find single-function defects (SQLi, injection, DoS,
secrets) but **0 cross-function authorization defects** — the exact class codefix
detects, repairs, and exploit-verifies. Pysa and CodeQL ship x86_64-only binaries;
on this aarch64 host they were run via qemu/amd64 emulation (`tonistiigi/binfmt`),
so the whole baseline is reproducible anywhere (see `bench/repro/`).

**The deeper finding:** even CodeQL — the one tool whose `BarrierGuard` *could*
express our ownership-dominance check — finds 0 BOLA out-of-box, because
authorization is application-specific (no generic "owner" query). That is not a
knock on CodeQL; it is direct evidence that cross-function authorization is not
expressible by generic rules, which is codefix's motivating premise.

