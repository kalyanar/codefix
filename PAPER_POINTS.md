# Paper talking points — what the prototype demonstrates, vs. other tools

Each point is a claim we can now back with running code in `codefixv2/`, the
paper section it serves, and how it compares to the relevant prior tool.

---

## The five demonstrable claims

### C1. Exploit-verified repair (not test-pass, not "the LLM said so")
A fix is recorded as success only if an **exploit reproducer succeeds before and
fails after, and the legitimate path is preserved** — shown over HTTP against
live dockerized VAmPI and on in-process fixtures.
- **Paper:** VI (Repair), II.D (vs APR), Novelty (vs caching).
- **Vs others:** APR (GenProg/SemFix) targets functional tests, not security
  oracles; LLM repair agents assert success; static tools don't fix at all.
  *No prior repair system gates on exploit reproduction + behavior preservation.*

### C2. Name-independent, cross-function detection (guard absence on a path)
Detection keys on the **shape** "a guard that dominates the sink on the path,"
not on identifier names. Demonstrated: renamed identifiers still caught; a guard
in a helper named `gate()` (down the chain) and in an `@admin_required`
decorator (up the chain) both clear the sink.
- **Paper:** III.E, V (Alg 1–2), VI (robustness-under-renaming), IV.B (formalism).
- **Vs others:** Bandit/Semgrep default rules are file-local and name/pattern
  based → 0 cross-function BOLAs (our baseline doc). CodeQL *can* express this
  via `BarrierGuard` but needs hand-authored queries and has no ownership
  built-in. We adopt the barrier-guard idea and add the layers below.

### C3. Facet fingerprint → robustness + the right granularity
The fingerprint is a **path-semantic facet tuple** (detector, source_role,
sink_category, missing_guard_class, fix_locus, framework), not a structural hash.
Demonstrated: flat (callees=0) and nested (callees=1) versions of one BOLA get
the **same** fingerprint; a topology hash gives two.
- **Paper:** III.D, IV.A (system model), IV.D (transfer/PAC bound).
- **Vs others:** code-clone fingerprints (VUDDY/ReDeBug) hash normalized AST →
  brittle to exactly this variation. Semantic-cache keys (GPTCache) are
  embedding-of-prompt, not a defect identity. *Keying repair memory on a
  path-semantic defect identity is new.*

### C4. Store invariance + cross-codebase transfer (F2)
3 structurally-different BOLA apps → **1** memory row, one shared posterior; a
fix learned on app A **warm-starts** app B (no LLM, exploit-verified),
re-rendering the concrete diff per codebase.
- **Paper:** VI.D (generalization), the headline F2 result, I.B/I.C.
- **Vs others:** no static analyzer, APR system, or agent (stateless) carries
  verified fix knowledge across codebases. Agent memories store episodic traces
  by similarity with no ground-truth verification and no transferable artifact.
  *Cross-codebase, exploit-verified, transferable repair memory is the contribution.*

### C5. Learning that compounds + can patternise
Per-(fingerprint,template) Beta posteriors update only on exploit-verified
outcomes (0.50→0.67→… as successes accrue); designed hierarchical prior lets new
fingerprints borrow strength from their pattern (cold-start + transfer).
- **Paper:** III.G, IV.C (Thompson regret), VI (greedy-vs-Thompson, learning curve F1).
- **Vs others:** no security tool has an outcome-driven, self-correcting fix
  selector. Bandits in SE exist; *per-defect-pattern, exploit-fed posteriors with
  partial pooling are new here.*

---

## One-line comparison table (for I.A / II)

| Capability | Bandit/Semgrep | CodeQL | Pysa | LLM agent | APR | GPTCache | **codefix** |
|---|---|---|---|---|---|---|---|
| Cross-function detection | ✗ | ✓ (queries) | ✓ (taint) | partial | ✗ | — | ✓ |
| Name-independent guard test | ✗ | ✓ (BarrierGuard) | partial | ~ | ✗ | — | ✓ |
| Auto-fix | partial | ✗ | ✗ | ✓ | ✓ | — | ✓ |
| **Exploit-verified fix** | ✗ | ✗ | ✗ | ✗ | ✗ (func tests) | — | **✓** |
| **Structure-invariant defect identity** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| **Cross-codebase transfer of fixes** | ✗ | ✗ | ✗ | ✗ | ✗ | ~ (replay) | **✓** |
| **Outcome-learned selection** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |

The bolded rows are where codefix is alone. The unbolded rows are where it
*adopts* established ideas (and should cite them, not claim them).

---

## Honest verdict (does this make a good paper addition?)

**Yes — the bolded rows are a genuine, defensible delta**, and they are now
backed by running code rather than promises. The contribution is not "we detect
BOLA" (CodeQL/Pysa do) or "we fix code" (APR/agents do) — it is the **stack no one
else has**: exploit-verified repair + a structure-invariant defect identity +
cross-codebase transfer + outcome-learned selection.

**Where to be careful (or a reviewer bites):**
- Detection precision/recall must be shown vs CodeQL/Pysa on a real corpus (M5);
  do not claim detection superiority — claim the *repair-and-learning* layer.
- The structural-matcher is an approximation; for soundness, position CodeQL/Pysa
  as finding sources and codefix as the layer above (consume, don't compete).
- F1 (learning curve) and F2 (transfer) must come from the real benchmark, not
  only the toy fixtures — the toy proves the mechanism; the paper needs scale.
- Cite lineage honestly: BarrierGuard (CodeQL), code-clone hashing (VUDDY),
  bandits in SE, semantic caches — and locate novelty in the *combination*.

**Net:** the prototype converts the two reviewer-fatal gaps (no security oracle,
anecdotal/no-transfer) into demonstrated capabilities, and adds a defensible new
primitive (structure-invariant, transferable, verified repair memory). That is a
publishable core — provided the evaluation is run at corpus scale (M1–M12).
