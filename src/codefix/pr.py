"""PR output. A verified fix is surfaced as a reviewable pull request whose body
carries the four executed validator stages as evidence, plus the exact diff the
validator applied. We never open a PR for an unverified change.

In the prototype this produces the PR artifact (title + markdown body); the same
payload can be opened via ``gh`` / the GitHub API.
"""
from __future__ import annotations

from dataclasses import dataclass

_CLASS_TITLE = {
    "BOLA": "broken object level authorization",
    "BFLA": "broken function level authorization",
    "MASS_ASSIGNMENT": "mass assignment",
    "SSRF": "server-side request forgery",
    "MISSING_AUTH": "missing authentication",
}
_GUARD_TITLE = {
    "ownership": "ownership guard", "role": "role guard", "authn": "authn guard",
    "url_validation": "URL validation", "field_allowlist": "field allowlist",
}
_STAGE_TEXT = {
    "exploit-blocked": "exploit blocked on patched endpoint",
    "differential-legit": "legitimate path preserved (differential)",
    "contract-conformance": "response contract holds",
    "adversarial-bypass": "adversarial variant blocked",
}


@dataclass
class PRDraft:
    title: str
    body: str

    def write(self, path: str):
        with open(path, "w") as f:
            f.write(f"# {self.title}\n\n{self.body}\n")


def make_pr_draft(app: str, result, exploit_name: str = "exploit.py") -> PRDraft | None:
    if result.status != "success":
        return None
    cls_desc = _CLASS_TITLE.get(result.issue_class, result.issue_class)
    guard = _GUARD_TITLE.get(result.missing_guard_class, result.missing_guard_class or "guard")
    title = f"fix(security): {result.issue_class} in {result.func} — {cls_desc}"
    stages = "\n".join(f"- [{'x' if ok else ' '}] {_STAGE_TEXT.get(name, name)}"
                       for name, ok in (result.stages or []))
    prov = {"template": "exact template (memory)",
            "fuzzy": "near-neighbour recall, promoted to exact",
            "llm_cold": "LLM cold path, promoted to template"}.get(result.provenance,
                                                                  result.provenance)
    body = f"""## exploit-verified fix · {result.issue_class} · {guard}
{stages}

```diff
{result.rendered_diff.rstrip()}
```

`{result.issue_class}` in `{app}::{result.func}` — {cls_desc}. The reproducer
`{exploit_name}` succeeds before this patch and is blocked after it; each box
above is an executed check against a sandboxed copy of the code.

- source: {prov}
- selection posterior: {result.posterior:.3f}

> verified by codefix · fingerprint: {result.fp_label} ({result.fp_hex})"""
    return PRDraft(title, body)
