"""Candidate generation + the BOLA ownership-guard template (transform).

A template names a transform_id + params; rendering produces a concrete,
parameterized edit against the *current* code (here: insert an ownership
guard after the sink, keyed on the sink's bound variable). The literal text is
repo-specific; the recipe transfers.
"""
from __future__ import annotations

from dataclasses import dataclass

from .detect import Finding
from .memory import TemplateStat

# Built-in template registry for the authorization family (the classes our
# approach fits). transform_id -> apply behaviour in validate.py.
#   exploit-verified end-to-end in the slice: BOLA, BFLA
#   declared (detection spec / fixtures pending, M4/M8): missing_auth, SSRF, mass_assignment
BUILTIN_TEMPLATES = [
    {"name": "bola_ownership_guard", "issue_class": "BOLA",
     "transform_id": "insert_ownership_guard"},
    {"name": "bfla_role_guard", "issue_class": "BFLA",
     "transform_id": "insert_role_guard_at_start"},
    {"name": "missing_auth_guard", "issue_class": "MISSING_AUTH",
     "transform_id": "insert_authn_guard_at_start"},
    {"name": "ssrf_validate_guard", "issue_class": "SSRF",
     "transform_id": "insert_url_validation_before_sink"},
    {"name": "mass_assignment_allowlist", "issue_class": "MASS_ASSIGNMENT",
     "transform_id": "insert_field_allowlist"},
]


@dataclass
class Candidate:
    template_id: int
    name: str
    transform_id: str
    alpha0: float
    beta0: float
    successes: int
    regressions: int
    provenance: str        # 'template' | 'fuzzy' | 'llm_cold'
    rendered_diff: str
    rationale: str = ""

    def posterior_mean(self) -> float:
        a = self.alpha0 + self.successes
        b = self.beta0 + self.regressions
        return a / (a + b)


def render_fix(finding: Finding) -> str:
    """Render the concrete fix for THIS codebase. Parameterized per-codebase
    (owner field inferred), so the same template is a recipe, not a frozen diff."""
    if finding.transform_id == "insert_ownership_guard":
        obj, of = finding.sink_assign_target, finding.owner_field
        return (
            f"# ownership guard after line {finding.sink_lineno} in {finding.func}\n"
            f'+    if {obj} is not None and {obj}["{of}"] != current_user_id():\n'
            f'+        raise PermissionError("not owner")\n'
        )
    if finding.transform_id == "insert_role_guard_at_start":
        return (
            f"# role guard at start of {finding.func}\n"
            f'+    if current_user() is None or current_user().get("role") != "admin":\n'
            f'+        raise PermissionError("forbidden")\n'
        )
    if finding.transform_id == "insert_field_allowlist":
        dv = finding.sink_assign_target
        return (
            f"# field allowlist before mass-assignment in {finding.func}\n"
            f"+    {dv} = {{k: {dv}[k] for k in ALLOWED_FIELDS if k in {dv}}}\n"
        )
    if finding.transform_id == "insert_url_validation_before_sink":
        url = finding.sink_assign_target
        return (
            f"# URL validation before fetch in {finding.func}\n"
            f"+    if not is_safe_url({url}):\n"
            f'+        raise PermissionError("blocked url")\n'
        )
    if finding.transform_id == "insert_authn_guard_at_start":
        return (
            f"# authentication guard at start of {finding.func}\n"
            f"+    if current_user() is None:\n"
            f'+        raise PermissionError("authentication required")\n'
        )
    return f"# (no renderer for {finding.transform_id})\n"


def candidates_for(finding: Finding, stats: list[TemplateStat]) -> list[Candidate]:
    """Strategy `template`: candidates from recalled templates (the fallback)."""
    out: list[Candidate] = []
    for s in stats:
        out.append(Candidate(
            template_id=s.template_id, name=s.name, transform_id=s.transform_id,
            alpha0=s.alpha0, beta0=s.beta0, successes=s.successes,
            regressions=s.regressions, provenance="template",
            rendered_diff=render_fix(finding),
        ))
    return out


def llm_candidate(finding: Finding, provider) -> Candidate | None:
    """Strategy `llm`: ask the configured provider to propose a fix. Returns a
    cold candidate (template_id=None); on verified success the orchestrator
    promotes it to a template so the next codebase warm-starts without the LLM."""
    proposal = provider.propose(finding)
    if proposal is None:
        return None
    finding.transform_id = proposal.transform_id  # the model chose the transform
    return Candidate(
        template_id=None, name=f"llm:{provider.name}", transform_id=proposal.transform_id,
        alpha0=1.0, beta0=1.0, successes=0, regressions=0,
        provenance="llm_cold", rendered_diff=render_fix(finding),
        rationale=proposal.rationale,
    )
