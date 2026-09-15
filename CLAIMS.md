# Claims ledger — paper (`codefix.tex`, submitted) and site (codefix.milepath.life)

The paper and the site are frozen. This file maps every technical claim they make
to the code, test or run that makes it true on branch `paper-match`, or records the
measured value where a run produces a number. Nothing here was tuned to hit a
published figure.

Legend: ✅ true in code (evidence) · 📏 measured (claimed → measured) · ⚠️ not a code
claim / cannot be made true by code (explained)

Test files: `tests/test_slice.py` (S), `tests/test_mechanisms.py` (M),
`tests/test_cli.py` (C), `tests/test_scip.py` (P).

## Architecture (paper §III, site Architecture / Plain English / Mechanisms)

| Claim | Status | Evidence |
|---|---|---|
| CodeMap: cross-file call graph; FunctionNode = fqname, parent class, file, line range, params, decorators, AST handle | ✅ | `graph.py` · M `test_codemap_three_pass_cross_file` |
| CallEdge = caller fqname, callee name as written, resolved fqname or None, line; unresolved external calls kept with raw name | ✅ | `graph.CallEdge` (+ import-qualified `callee_symbol`) · M same test |
| Three-pass build; relative imports resolved; sibling methods resolved | ✅ | `graph.build` · M same test |
| Builder records intra-procedural def-use edges and decorator edges | ✅ | `CodeGraph.defuse`, `decorator_edges` · M same test |
| Rebuilt per scan, never persisted (no stale AST) | ✅ | `orchestrate.run_once` builds per run |
| "A 30–50 file repository builds in ≈50 ms" | 📏 | crAPI workshop 41 files **20.7 ms**, pygoat 50 files **33.7 ms**, VAmPI 11 files 5.7 ms (median of 20, `bench/experiments.py`) |
| Engine consumes a declarative spec and runs against any CallGraphProvider; SCIP-derived graphs (scip-python / scip-typescript) are another provider | ✅ | `detect.py` reads only provider IR; `scipgraph.py` · P all tests (TypeScript via scip-typescript) |
| Site: "SCIP-backed provider implements the same graph interface — the cross-function analysis runs on any SCIP-indexed language (TypeScript, Java, Go…) without touching the engine" | ✅ (TypeScript demonstrated) | P `test_same_engine_detects_the_typescript_bola_across_three_modules`, `test_dominance_holds_on_the_scip_provider`. Java/Go are brace languages the provider parses the same way but were not run here |
| Spec = flow shape, sink matcher (method names, name regexes, receiver regexes, decorators), mitigation matcher (call names, decorators), search direction callees / callers / both / callers_and_self | ✅ | `detect.SinkMatcher`, `DetectorSpec(call_anchors, decorator_anchors, direction)` |
| Mitigation walk = bounded BFS in the spec's direction; decorators vs allowlist; outgoing call leaf names vs allowlist; default depth 2; leaf-name match robust to dotted access | ✅ | `detect._protected`, `_up_protected`, `taint.has_anchor` · S `test_m13c_*`, M `test_callers_search_requires_every_caller_to_be_guarded` |
| A match counts only if it is a **denying** guard that **dominates** the sink (skippable branch / logging check don't count) | ✅ | `ir.FunctionBody.guard_protects` (CFG dominators) · S `test_m3_*`, M `test_guard_after_the_data_escapes_does_not_count` |
| Name-independent: guard renamed `gate()` counts; search up into decorators/callers and down into helpers | ✅ | S `test_guard_in_differently_named_helper_is_not_flagged`, `test_decorator_demo_bfla_decorated`, M `test_guard_helper_in_another_module_clears_by_shape` |
| Def-use taint to a fixpoint (assignment chains, attributes, call returns) | ✅ | `taint.taint_closure` · S `test_m3_taint_through_assignment_chain` |
| Within-function and one-hop-helper taint flows modelled | ✅ (up to spec depth, default 2) | `detect._bind` · M `test_bola_across_three_modules_is_detected_fixed_and_verified` |
| SSRF / missing-auth sinks anchor on resolved library symbols | ✅ SSRF (`urllib.request.urlopen`, `requests.*`, `httpx.*`); missing-auth uses the spec's name-regex sink as Alg. 1 allows | M `test_ssrf_anchors_on_library_symbols_not_helper_names` |
| Facet fingerprint: issue class, source role, sink category, missing guard, fix locus, framework — read off the path | ✅ | `fingerprint.compute`; roles from taint origin, locus from where the guard goes · M `test_facets_are_read_off_the_path` |
| Structure-invariance: flat / nested / renamed / extra-helper → one key | ✅ | M `test_structure_invariance_flat_nested_renamed_extra_helper` (4 fixtures) |
| Store-invariance: three different BOLA apps → one row, one posterior (site "3 → 1") | ✅ | S `test_store_invariant_to_structure` |
| Precondition bitmask + framework-independent embedding for fuzzy recall | ✅ | `fingerprint.embedding`, `precondition_mask` |
| TemplateSpec = transform + params (guard helper, user reference, import) filled from the target's own AST; one template applies unchanged across codebases | ✅ | `templates.py` (`discover`: owner field and access style, principal accessor incl. cross-module import, existing guard helper / guard decorator / URL validator / allow-list, the codebase's own guard idiom and denial statement) · M `test_template_renders_in_the_target_codebases_idiom`, S `test_transfer_demo_cross_domain` |
| Four-stage validator — exploit, differential, contract (response schema), adversarial — **all** must pass | ✅ | `validate.verify` (a missing stage = `unverified`) · S `test_full_validator_stack`, M `test_a_missing_stage_is_unverified_not_success` |
| A fix that strips a response field is caught by the contract stage (site "contract demo") | ✅ | M `test_contract_stage_rejects_a_fix_that_strips_a_response_field`, S `test_contract_demo_field_strip_is_caught` |
| An overfit guard (blocks one victim) is caught by the adversarial stage | ✅ | S `test_adversarial_bypass_catches_overfit`; every fixture ships `bypass.py` |
| Only a fix that clears all four stages is applied, remembered or surfaced as a PR; unverified → no PR, no posterior update | ✅ | `orchestrate.run_once`, `pr.make_pr_draft` · S `test_m11_pr_output`, M `test_a_missing_stage_is_unverified_not_success` |
| Recall exact → fuzzy (cosine + Hamming, neighbours that carry a verified template) → LLM constrained to the transform vocabulary; verified fuzzy/LLM fixes promoted to exact templates | ✅ | `memory.fuzzy_lookup`, `providers.ALLOWED_TRANSFORMS`, promotion in `run_once` · S `test_m7_fuzzy_recall_on_exact_miss`, `test_coldpath_llm_promotes_to_template` |
| PatchMemory: single SQLite file, eight FK-linked tables (codebases, fingerprints, issues, templates, template_fingerprint_links, patches, outcomes, detector_specs) | ✅ | `memory.SCHEMA` · M `test_patch_memory_has_eight_linked_tables_and_outcome_statuses` |
| Outcome statuses success / regression / reverted / superseded / applied_no_tests; β counts regressions ∪ reverts | ✅ | `memory.record_outcome`, `mark_reverted`, `mark_superseded` · M same test |
| `template_min_success_rate`: a template is "proven" past a threshold over a sufficient (PAC) sample | ✅ | `memory.is_proven`, `pac_min_observations` · S `test_auto_selection_explores_until_a_template_is_proven` |
| Per-(fingerprint, template) Beta posteriors; greedy by mean or Thompson under `--explore`; same posterior → unconfounded ablation | ✅ | `learn.py`; CLI `--explore` wired · S `test_greedy_and_thompson_share_the_beta_posterior`, C `test_default_verifies_learns_and_writes_pr_with_the_applied_diff` |
| Site: greedy for production once warm, Thompson while young | ✅ | `run_once(select="auto")`, `codefix scan --select auto` |
| Hierarchical prior: cold fingerprint inherits its family's rate (0.65 from 2 prior BOLA successes); empty family 0.5 | ✅ | S `test_m8_hierarchical_prior_patternise` |
| Feature-flagged contrastive embedding, off by default | ✅ | S `test_m9_feature_flag_off_by_default` |
| Non-gating triage: full permutation, wrong tags cannot cause a miss | ✅ | S `test_m10_*` |
| Developer-extensible catalog: propose → self-test gate (schema, planted bug, exploit-verified fix, structure invariance, idempotency) → persist → fresh engine runs it (IDOR_NOTE); off-vocabulary spec rejected | ✅ | `authoring.run_gate` (all five transforms gated) · S `test_m13_extensible_catalog_lifecycle`, `test_authoring_gate_admits_valid_and_rejects_bad` |
| Site Extensibility: `DetectorSpec(issue_class="IDOR_NOTE", sink=call("get_note", arg="note_id"), missing_guard="ownership", search=UP, fix_template="insert_ownership_guard")` — a ~25-line literal, no engine change | ✅ | `bench/apps/new_issue_idor_note/new_detector.py` is that literal; loaded by S `test_m13_extensible_catalog_lifecycle` |
| Every phase emits an event; a run is a replayable trace | ✅ | perceive, triage, detect, fingerprint, recall, select, propose, act, validate, learn · S `test_m11_event_stream` |
| Real LLM provider (Anthropic) wired | ✅ | `providers.AnthropicProvider` (`--provider anthropic`); tests use the mock |

## Integration (site)

| Claim | Status | Evidence |
|---|---|---|
| `--detect-only`: findings as PR comments, no changes, good for CI gating | ✅ | C `test_detect_only_reports_review_comments_and_changes_nothing` |
| `--dry-run`: which fixes would apply and exploit-verify, nothing written | ✅ | C `test_dry_run_verifies_in_sandbox_without_writing` |
| default: apply in sandbox, verify all four stages, PR with evidence checkboxes + diff | ✅ | C `test_default_verifies_learns_and_writes_pr_with_the_applied_diff`; `--apply` writes into the tree (C `test_apply_writes_the_verified_fix_and_a_rescan_is_clean`) |
| `codefix scan /repo --db /shared/codefix.db --explore --pr ./out` nightly | ✅ | `cli.py` |
| PR body format (`## exploit-verified fix · BOLA · ownership guard`, four `[x]` stages, diff, `> verified by codefix · fingerprint: …`) | ✅ | `pr.py` · S `test_m11_pr_output`; real drafts in `bench/live_results/*.md` |

## Evaluation (paper §V, site Results / Testing / OWASP / Milestones)

| Claim | Status | Evidence |
|---|---|---|
| In-process fixtures for all five classes with safe/unsafe pairs and flat/nested/renamed/extra-helper variants | ✅ | `bench/apps/*`, `bench/apps/safe_pairs/*`, `bench/apps/bola_variants/*` · S `test_safe_twins_of_all_five_classes_are_clean` |
| All five classes detected, fixed, exploit-verified, each through the full four-stage validator; no collision | ✅ | S `test_m4_*`, `test_end_to_end_exploit_verified` |
| SSRF fix blocks the 169.254.169.254 metadata fetch; mass-assignment allow-list blocks `is_admin`; missing-auth blocks unauthenticated transfer | ✅ | S `test_m4_ssrf_exploit_verified`, `test_m4_mass_assignment_end_to_end`, `test_m4_missing_auth_exploit_verified` |
| VAmPI object-read BOLA and password takeover: exploit-confirmed before the fix and **blocked after [codefix's] fix**, owner path preserved (site: succeeds on :5002, blocked on :5001) | ✅ | `bench/live_codefix.py vampi` — codefix scans VAmPI's source, renders `book.user.username != resp['sub'] → abort(403)` and the takeover guard; both containers run `vulnerable=1`, :5001 serves codefix's tree; all four stages pass for both defects (`bench/live_results/vampi_*.json`) · S `test_live_vampi_dockerized_http` (CODEFIX_LIVE=1) |
| crAPI shop-order BOLA exploit-confirmed before and blocked after the fix, owner path preserved | ✅ | `bench/live_codefix.py crapi` — codefix renders `@jwt_auth_required` + `if user != order.user: return Response(RESTRICTED, 403)` from crAPI's own `put()` idiom; the workshop image is rebuilt from codefix's tree; all four stages pass (`bench/live_results/crapi_*.json`) · S `test_live_crapi_ten_container_app` |
| crAPI leak "including full payment-card details" | ⚠️ | crAPI's payment gateway masks the PAN to the last four digits (`XXXXXXXXXXXX8605`) and returns owner name, card type, expiry — the full card *record*, not the full number. App behaviour, not codefix code (`bench/apps/crapi/DEFECTS.md`) |
| Transfer (F2): cold 1 LLM call → warm 0 on a structurally different codebase, 2/2 verified | 📏 ✅ | cold **1**, warm **0**, **2/2** (`bench/experiments.py`) · S `test_m12_experiment_figures` |
| F1: LLM-call rate 1.0 → 0.12 over 42 issues at 1.00 success (site "88%") | 📏 ✅ | **0.119** at **1.00** over 42 issues, with real cross-file detection, AST-rendered fixes and all four stages |
| Thompson bounds worst-case regret to 14 vs greedy 70 (adversarial cold start, same posterior) | 📏 | now run through codefix's selector over PatchMemory posteriors (worse template seeded with an early lucky success, pA 0.80 / pB 0.45, 200 rounds, 30 seeds): greedy **69.7** (claimed 70), Thompson **20.0** (claimed 14). The shape holds (Thompson's tail ≈ 3.5× smaller); the Thompson figure does not reproduce |
| Contrastive: transferred pair cos → 1.0, regressed pair → 0.13; framework weight → 0; nested-context up-weighted | 📏 ✅ | cos **1.00 / 0.132**, `fw:*` **0.0**, `ctx:nested` **13.0**; the transferred pair is mined from PatchMemory after verified runs, the regressed nested-context pair is labelled |
| Triage: cost-to-first up to 5 → 1, recall identical; wrong tags still find SSRF | 📏 ✅ | worst **5 → 1** across the five class fixtures, recall equal, SSRF found with wrong tags |
| Baselines: Bandit 1.9.4, Semgrep 1.166.0, Pysa, CodeQL (BarrierGuard) find 0 cross-function authz; their native findings | see below | `bench/baselines.py`, `bench/RESULTS_baselines.md` |
| "Full suite (29 tests)" / site "29 passing tests" | ⚠️ | the mechanisms the paper describes needed more tests: the suite is now 70 (68 + 2 live, all passing with CODEFIX_LIVE=1). Every test named on the site exists and passes. The count is a number about the suite, not a mechanism |

## Not code claims

| Claim | Why |
|---|---|
| OWASP statistics (BOLA+BFLA ≈ 90 %, missing authentication 52 %) | external literature |
| Authors / affiliation, "13 milestones complete", "reproducible linux/amd64 image" branding | project facts, not mechanisms |
| Site Honesty: "CodeQL has no arm64 build" | a fact about CodeQL's distribution (see baselines report) |
| Site Transfer example code (`@app.get("/books/<bid>")`, `b.owner != current_user`) and the Integration PR sample (`def get_order(order_id, current_user)`) | illustrations; the real equivalents are `library_flat_bola` (transfer) and `bench/live_results/*.md` (PR bodies) |
