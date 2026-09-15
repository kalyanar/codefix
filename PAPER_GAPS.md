# Paper ↔ code gaps (codefixv2 vs `codefix.tex`)

Audit of every mechanism and result the paper claims, against the code on `main` (d7a3a3e).
Rule for fixing: **change the code so it does what the paper says**; where a *number* moves once the
mechanism is real, report the measured number — never tune code to reproduce a figure.

Status: ✅ matched · 🔧 fixed on `paper-match` · 📏 measured (paper number to update) · ⛔ blocked (reason)

## §III.B CodeMap — cross-file call graph
| Paper | Code on main | Status |
|---|---|---|
| `FunctionNode` = fqname, parent class, file, line range, params, decorators, AST handle | name, node, params, lineno, decorators; **one file**, bare names (methods collide) | 🔧 |
| `CallEdge` = caller fqname, callee name as written, resolved fqname or None, line | `calls: name -> set(names)`, only same-file callees kept; unresolved calls dropped | 🔧 |
| three-pass build; imports incl. relative resolved; sibling methods | single pass over one file, no imports | 🔧 |
| intra-procedural def-use edges + decorator edges recorded | not recorded (taint recomputed ad hoc) | 🔧 |
| rebuilt per scan, not persisted | ✅ | ✅ |
| "30–50 file repository builds in ≈50 ms" | never measured for v2 | 📏 |

## §III.E / Alg. 1–2 Generic engine
| Paper | Code on main | Status |
|---|---|---|
| runs against any `CallGraphProvider` (CodeMap; SCIP-derived graphs) | no provider protocol; no SCIP in v2 | 🔧 |
| mitigation walk = bounded BFS: decorators ∈ allowlist, outgoing call leaf-names ∈ allowlist, directions callees / callers / both / callers_and_self, default depth 2 | direction up/down/both only; **no callers search**; depth ignored for guards | 🔧 |
| a match counts only if a **denying** guard that **dominates** the sink | "top-level `if` anywhere in body" — a guard *after* the exposure still counted | 🔧 |
| one-hop-helper taint flows modelled | intra-procedural only | 🔧 |
| sink predicate S_c (data-access / fetch / write / privileged / sensitive) | BOLA sink = *any* `x = call(tainted)` (e.g. `oid = int(order_id)`) | 🔧 |
| SSRF / missing-auth sinks anchor on **resolved library symbols** | bare name sets (`fetch_url`, …); `requests.get` not a sink | 🔧 |

## §III.F Templates and producers
| Paper | Code on main | Status |
|---|---|---|
| `TemplateSpec` = transform + params (guard helper, user reference, import), filled **from the target's own AST** | guard text hard-coded (`current_user_id()`, `raise PermissionError`) in two places (`render_fix` text ≠ `_apply_fix` edit) | 🔧 |
| renderer (`render_patch`) materializes the fix applied *and* shown in the PR | PR "diff" is a hand-built snippet, not the applied change | 🔧 |

## §III.G Four-stage exploit-verified validator
| Paper | Code on main | Status |
|---|---|---|
| exploit, differential, contract, adversarial — **all must pass** | contract + adversarial run only if `contract.py`/`bypass.py` exist (1 of 9 apps) | 🔧 |
| contract = response **schema** check; "a fix that strips a response field is rejected" | exact stdout compare; no test of the field-strip case | 🔧 |
| five classes each through the full validator | 4 of 5 classes had only 2 stages | 🔧 |

## §III.C / §IV.A PatchMemory
| Paper | Code on main | Status |
|---|---|---|
| 8 FK-linked tables: codebases, fingerprints, issues, templates, template_fingerprint_links, patches, outcomes, detector_specs | 6 tables (no codebases, no issues; `links`), no foreign keys | 🔧 |
| outcome statuses success / regression / reverted / superseded / applied_no_tests; β counts regressions ∪ reverts | success / regression only | 🔧 |
| `template_min_success_rate`: a template is "proven" past a threshold over a sufficient sample (§IV.D) | absent | 🔧 |

## §III.I Selection · §III.K catalog
| Paper | Code on main | Status |
|---|---|---|
| Thompson under `--explore` | CLI parses `--explore` but never passes it to `run_once` | 🔧 |
| gate verifies the spec's fix for any transform in the registry | `KNOWN_TRANSFORMS` = 2 of 5 transforms | 🔧 |

## §V Evaluation
| Paper | Code on main | Status |
|---|---|---|
| Tab. III: baselines *ran* and report 0 cross-fn authz | Bandit/Semgrep authz column **hard-coded 0**; Pysa/CodeQL only in a markdown log | 🔧 (classifier over real tool output) |
| codefix detects on VAmPI / crAPI | codefix **never scans VAmPI** (`app_py=None`, "single-module" note) | 🔧 |
| VAmPI BOLA + password takeover "blocked after [codefix's] fix" | vulnerable container vs VAmPI's own *secure* container — no codefix fix applied | 🔧 |
| crAPI shop-order BOLA blocked after fix | only "exploit works before"; no after | see crAPI note |
| Thompson worst-case regret 14 vs greedy 70 "under adversarial cold start … same Beta posterior" | synthetic two-arm Bernoulli sim, not codefix's selector, no adversarial seed | 🔧 → 📏 |
| contrastive: cosine 1.0 vs 0.13; framework weight → 0; nested-context up-weighted | not produced by any script | 🔧 → 📏 |
| triage: cost-to-first 5 → 1; wrong tags still find SSRF | unit tests only, no recorded figure | 🔧 → 📏 |
| structure-invariance over flat / nested / renamed / extra-helper variants | flat vs nested only | 🔧 |
| F1 1.0 → 0.12 over 42 issues at 1.00 success; F2 2/2 at 0 LLM calls | 42 = 7 fixtures × 6 shuffles (mock LLM) — consistent with "stream drawn from the corpus"; re-measured after the fixes | 📏 |
| "full suite (29 tests)" | 35 before this branch | 📏 |
