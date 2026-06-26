# Benchmark corpus — curated by defect class

Many deliberately-vulnerable apps ship docker images that security tools
benchmark against. **But most are injection/XSS/config-focused and exercise
codefix's classes (cross-function BOLA/BFLA, SSRF, mass-assignment) weakly or not
at all.** The corpus must be curated by *defect class*, not by "is it a known
vulnerable app." Adding an app where codefix's scope isn't exercised produces a
misleading zero, not a result.

## Fit by app (does it exercise codefix's cross-function authz classes?)

| App | Docker | BOLA/BFLA | SSRF | Mass-assign | Fit | Notes |
|---|---|---|---|---|---|---|
| **VAmPI** | ✓ (vendored) | ✓✓ (books BOLA, user BFLA) | — | — | **strong** | in corpus; live HTTP exploit working |
| **crAPI** (OWASP) | ✓ (multi-container) | ✓✓✓ (vehicle/order BOLA, mechanic BFLA) | ✓ | ✓ | **strong** | **IN CORPUS** — shop-order BOLA exploit-confirmed (attacker reads victim's order + PCI card data). 10 containers; Python workshop service is codefix-analyzable. No secure variant (exploit = ground truth) |
| **DVGA** (Damn Vulnerable GraphQL) | ✓ | ◐ (some authz) | — | — | partial | GraphQL resolvers; different shape |
| **OWASP Juice Shop** | ✓ | ◐ (basket/feedback IDOR) | — | — | partial | JS/TS; some broken-access-control; mostly XSS/injection |
| **pygoat** | ✓ (vendored) | ✗ (cookie-trust, not object-id) | ◐ (ssrf_lab) | — | **weak** | access lab is client-trust; useful as SSRF target later + negative example |
| **DVWA** | ✓ | ✗ | — | — | weak | SQLi/XSS/CSRF/command-injection; single-function |
| **WebGoat** | ✓ | ◐ (one IDOR lesson) | — | — | weak | mostly injection/auth lessons; Java |
| **NodeGoat** | ✓ | ◐ (A4 access control) | ✓ | — | partial | Node; has access-control + SSRF lessons |

✓✓✓/✓✓/◐/✗ = how richly the app exercises codefix's classes.

## What this means for the paper

- **Strong-fit corpus = VAmPI + crAPI** (real, API-focused, BOLA/BFLA/mass-assign).
  These are where the detection/repair/transfer numbers come from.
- **Partial-fit (Juice Shop, NodeGoat, DVGA)** add breadth/cross-language once the
  relevant detection (SSRF, GraphQL) lands — good for generalization claims.
- **Weak-fit (pygoat, DVWA, WebGoat)** are **negative-control / scope-boundary**
  evidence: codefix should *not* fire on their out-of-scope flaws (cookie-trust,
  SQLi, XSS) — a clean "no false positives outside scope" result, and a place to
  exercise SSRF (pygoat/NodeGoat) once that detector exists. Do **not** count
  their out-of-scope flaws as misses.

## Recommendation

Next real-corpus addition: **crAPI** (genuinely BOLA/BFLA/mass-assignment rich,
the closest public app to codefix's target class). pygoat stays vendored as a
**negative-control + future SSRF** target, not a BOLA/BFLA benchmark. This keeps
the corpus honest: every app is there because it exercises (or deliberately does
not exercise) a class we target.
