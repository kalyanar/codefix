# OWASP coverage — API Top 10 (2023) + LLM Top 10 (2025)

How codefix handles each OWASP category. Status is one of: **handled**
(detect → fix → exploit-verify), **detect-only/partial**, or **scoped-out**
(different reasoning; complementary tool). Decision (per design): build
fixes for the **authorization family** the approach fits; honestly route the
rest. For the LLM Top 10, build only the **code-path subset**.

The principle that decides the split: codefix repairs **defects that are the
absence of a server-side check on the call path between user input and a
sensitive operation.** If a category is not that shape, it is scoped out.

---

## OWASP API Security Top 10 (2023)

| ID | Category | codefix | Status | Mechanism / reason |
|---|---|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | ✅ | **handled** (running) | tainted id → sink, no ownership guard on path → `bola_ownership_guard` |
| API2 | Broken Authentication | ◑ | **partial** | "sensitive op reachable with no authn step on path" → `missing_auth_guard` (declared). JWT crypto correctness = scoped-out (single-function) |
| API3 | Broken Object Property Level Authorization (incl. Mass Assignment) | ◑ | **partial** | mass assignment: user input → model, no field allowlist → `mass_assignment_allowlist` (declared). Property-level read filtering overlaps DLP (future) |
| API4 | Unrestricted Resource Consumption | ✗ | scoped-out | rate limits / payload caps / quotas = config + runtime, not a code-path check |
| API5 | Broken Function Level Authorization (BFLA) | ✅ | **handled** (running) | privileged op reachable, no role gate on path → `bfla_role_guard` |
| API6 | Unrestricted Access to Sensitive Business Flows | ✗ | scoped-out | bot/abuse detection, device fingerprinting, captcha = runtime/business |
| API7 | Server-Side Request Forgery (SSRF) | ◑ | **partial** | param → fetch sink, no URL validation on path → `ssrf_validate_guard` (declared) |
| API8 | Security Misconfiguration | ✗ | scoped-out | TLS/headers/debug-mode = config, not AST cross-function |
| API9 | Improper Inventory Management | ✗ | scoped-out | API inventory/lifecycle/versioning = ops, not a code defect |
| API10 | Unsafe Consumption of APIs | ◑ | future | trusting third-party responses → a taint-from-external-response shape; expressible later |

**Authorization family (the approach's wheelhouse):** API1, API5 handled and
exploit-verified end-to-end in the slice; API2, API3(mass-assign), API7 declared
in the template registry with detection specs (fixtures pending, M4/M8).

---

## OWASP Top 10 for LLM Applications (2025) — code-path subset only

codefix is a code-repair layer, not an LLM-runtime guard. Most LLM-Top-10 items
are runtime/data/ops concerns. We build fixes only for items that are a
**code-path shape** in the application code that calls the model.

| ID | Category | codefix | Status | Mechanism / reason |
|---|---|---|---|---|
| LLM01 | Prompt Injection | ✗ | scoped-out | runtime input to the model; not an app code-path guard |
| LLM02 | Sensitive Information Disclosure | ◑ | future | overlaps DLP: model output / API response leaking PII → response-filter shape |
| LLM03 | Supply Chain | ✗ | scoped-out | dependency/model provenance = supply-chain tooling |
| LLM04 | Data & Model Poisoning | ✗ | scoped-out | training/data pipeline, not app code |
| LLM05 | Improper Output Handling | ◑ | **code-path shape** | unsanitized model output flowing into a sink (exec/SQL/HTML/shell) = taint→sink, no sanitizer on path. Same engine shape as our detectors → buildable |
| LLM06 | Excessive Agency | ◑ | **code-path shape** | over-broad tool/permission grant to the agent; an over-privileged call reachable with no scope check → a guard-absent shape → buildable |
| LLM07 | System Prompt Leakage | ✗ | scoped-out | prompt/config management |
| LLM08 | Vector/Embedding Weaknesses | ✗ | scoped-out | retrieval infra |
| LLM09 | Misinformation | ✗ | scoped-out | output quality, not a code defect |
| LLM10 | Unbounded Consumption | ✗ | scoped-out | rate/quota = runtime (cf. API4) |

**Buildable code-path subset:** LLM05 (improper output handling = model output →
dangerous sink with no sanitizer on the path) and LLM06 (excessive agency =
over-broad tool/permission reachable with no scope check). Both are the same
"guard-absent on the path" shape the engine already models; they are the natural
extension once the API authz family is solid. LLM02 overlaps the DLP
response-filter shape (future).

---

## The honest scope sentence (for the paper)

codefix repairs the OWASP categories that are **a missing server-side check on a
code path** — the authorization family (API1/API5 handled; API2/API3/API7
declared) — and, by the same mechanism, the code-path subset of the LLM Top 10
(LLM05 improper output handling, LLM06 excessive agency). It does **not** repair
config (API4/API8/API9), business-flow/abuse (API6), runtime LLM concerns
(LLM01/03/04/07/08/10), or single-function defects (SQLi/XSS/crypto) — these need
config tooling, runtime controls, supply-chain tooling, or single-function
analyzers (Semgrep/CodeQL/Bandit), which codefix complements rather than replaces.
