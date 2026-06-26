# Lecture-13 "How to Solve" → codefix coverage

Reconciles the remediation guidance in `CS6238_Lecture13_Spring2026.pdf`
(State of API Security) against the codefix design (`SPEC_GREENFIELD.md`,
`MILESTONES.md`). Every "how to prevent/solve" theme in the lecture is mapped to
one of: **handled** (codefix detects → fixes → exploit-verifies), **partial**
(detection or fix only, or a future template), or **scoped-out** (different
reasoning; belongs to a complementary tool) — with the reason.

---

## The crux (the one idea the lecture repeats)

> The dominant API failures — **BOLA + BFLA ≈ 90% of authorization failures,
> missing authentication = 52% of authentication failures** — are remediated by
> enforcing a **server-side check on the call path between user input and the
> sensitive operation** ("never trust the client"; "authorization checks should
> be considered in every function that accesses a data source using an ID from
> the user").

codefix is the automation of exactly this remediation:

- **Detect** = the cross-function mitigation-walk asks *"is a check present
  anywhere on the path from the tainted input to the sink?"* — the precise
  question the lecture says must be answered, and the one file-local tools cannot.
- **Fix** = a parameterized template *inserts the missing server-side check*
  (ownership / role / authn / validation) into the API code (not the UI).
- **Verify** = an exploit reproducer proves the check actually blocks the attack
  and preserves legitimate access.

So the lecture's #1 prescription maps 1:1 onto codefix's core loop. The "Trusted
Client Fallacy" slide (security must be server-side, never frontend/UI) is the
same point, and codefix enforces it structurally: detection runs on API code and
checks for a guard *on the server-side path*, not in client code.

---

## Coverage matrix

### Authentication (lecture: "Securing the Authentication Layer")

| Lecture remediation | codefix mechanism | Status | Milestone |
|---|---|---|---|
| Enforce authentication **server-side**, on the path to sensitive ops | `missing_auth` class: privileged/state-changing function reachable with no authn step on a caller path → insert authn guard | **handled** | M4/M8 |
| Validate JWT **signature / claims / expiration** every request | single-function crypto correctness, not cross-function | scoped-out | — (Semgrep/CodeQL rule; complementary) |
| Adopt strong schemes (OAuth) over static keys/basic auth | design/config choice, not a code-path defect | scoped-out | — |
| Exact full-path matching for public-endpoint exclusions (avoid bypass) | routing/config | scoped-out | — |

### Authorization (lecture: BOLA / BFLA — the headline)

| Lecture remediation | codefix mechanism | Status | Milestone |
|---|---|---|---|
| **Object-level**: ownership check in every function accessing a data source by user-supplied ID | `BOLA` detection (tainted id → data-access sink, no principal-comparison guard on path) → `bola_ownership_guard` template | **handled** (running in slice + VAmPI) | M4/M8 |
| **Function-level**: role/permission check; separate admin vs regular | `BFLA` detection (privileged function reachable with no role check on caller path) → `bfla_role_guard` template | **handled (to build)** | M4/M8 |
| Least privilege across object/role/function levels | expressed as the above two detection shapes | **handled** | M4/M8 |
| Authorization bypass via parameter tampering / business-logic chaining | semantic/business-logic; partially detectable | partial/future | M4 (future Tier) |

### Input Validation

| Lecture remediation | codefix mechanism | Status | Milestone |
|---|---|---|---|
| Mass assignment: process only user-modifiable fields (allowlist) | `mass_assignment` detection (user input → ORM `**kwargs`/model with no allowlist on path) → `mass_assignment_allowlist` template | **handled (to build)** | M4/M8 |
| SSRF: validate user-supplied URL before fetch | `SSRF` detection (param → fetch sink, no `validate_url` on path) → `ssrf_validate_guard` template | **handled (to build)** | M4/M8 |
| Schema validation / type enforcement / validate path-query-headers | partly a contract concern; checked by the **contract-conformance validator**, not auto-inserted | partial | M2 (validator) |
| SQL injection, command injection, XSS | single-function dataflow; Semgrep/CodeQL/Bandit territory | scoped-out | — (complementary) |
| API DoS: limit request sizes / expensive ops / response payloads | runtime/config (rate limits, payload caps) | scoped-out | — |
| Deserialization of malicious objects | single-function; complementary | scoped-out | — |

### Data Loss Prevention

| Lecture remediation | codefix mechanism | Status | Milestone |
|---|---|---|---|
| Filter unauthorized fields / data minimization in responses | candidate future template class: `response_field_allowlist` (insert response filtering on the path) | partial/future | future |
| PII/PHI never exposed inadvertently | needs data classification (what is PII) — not a pure code-path shape | scoped-out/future | — |
| Error hygiene: no internal info in errors | single-function; config/handler | scoped-out | — |
| User enumeration (valid vs invalid response differences) | behavioral/timing; dynamic-tool territory | scoped-out | — |

### Configuration & Inventory

| Lecture remediation | codefix mechanism | Status | Milestone |
|---|---|---|---|
| Missing rate limits | YAML/middleware/runtime, not AST cross-function | scoped-out | — |
| HTTPS not enforced / TLS | deployment config | scoped-out | — |
| Insecure framework / debug mode | config | scoped-out | — |
| Retire old APIs / zombie endpoints / data-flow blindspots | inventory/lifecycle, not a code-path defect | scoped-out | — |

### The AI Shift (8 emerging categories)

codefix's relationship here is **positioning**, not repair: it is the verified,
auditable repair layer *beneath* agents.

| Lecture category | codefix relationship | Status |
|---|---|---|
| Agent identity ambiguity / lack of audit trails | codefix records provenance + exploit-verified outcomes per patch → an audit trail for automated fixes | **addressed (audit story)** |
| Prompt-driven API misuse, function-calling abuse | codefix's LLM cold path is gated by deterministic exploit verification (LLM proposes, validators dispose) | addressed (design principle) |
| Hallucination-driven API risks | a hallucinated fix is rejected by the exploit/differential/contract validators before it can write to memory | addressed (design principle) |
| Token over-delegation, session/memory risks, quota abuse, model/schema injection, supply-chain | runtime/infra/identity concerns | scoped-out (out of repair domain) |
| AI-driven business-logic abuse | semantic; future | future |

---

## Remediation → template registry (in-scope classes)

Each in-scope lecture remediation becomes a triple: **detection shape (guard
absent on path) + parameterized fix template + exploit oracle**.

| Class | Detection shape | Fix template | Status |
|---|---|---|---|
| BOLA | tainted id → data sink, no ownership/principal guard | `bola_ownership_guard` | running (slice + VAmPI) |
| BFLA | privileged fn reachable, no role check on caller path | `bfla_role_guard` | to build (M4/M8) |
| Missing auth | sensitive fn reachable, no authn step on path | `missing_auth_guard` | to build (M4/M8) |
| SSRF | param → fetch, no URL validation on path | `ssrf_validate_guard` | to build (M4/M8) |
| Mass assignment | user input → model, no field allowlist on path | `mass_assignment_allowlist` | to build (M4/M8) |

---

## Honest scope statement (for the paper)

codefix **owns** the lecture's dominant remediation: server-side
authorization/authentication checks on the call path (BOLA, BFLA, missing auth),
plus SSRF and mass assignment — detected as guard-absent shapes and repaired with
exploit-verified templates. It **does not** address config/TLS/rate-limit, JWT
crypto correctness, SQLi/XSS/command-injection, DoS, PII classification, or
inventory/lifecycle — these need different reasoning (config, single-function
dataflow, data classification, runtime) and belong to complementary tools
(Semgrep, CodeQL, Bandit, API gateways, dynamic scanners). For the AI Shift,
codefix contributes the **verified-repair + audit-trail** layer beneath agents,
not runtime identity/quota controls.
