"""Candidate generation — the proposers (templates, fuzzy recall, the LLM).

Proposers only suggest: each candidate carries a `RenderedPatch` produced by
`templates.render_patch` from the target's own AST, and nothing is trusted
until the four-stage validator passes it.
"""
from __future__ import annotations

from dataclasses import dataclass

from .detect import Finding
from .memory import TemplateStat
from .templates import BUILTIN_TEMPLATES as _TEMPLATE_SPECS, RenderError, render_patch

# kept as plain dicts for the memory seeder
BUILTIN_TEMPLATES = [{"name": t.name, "issue_class": t.issue_class,
                      "transform_id": t.transform_id} for t in _TEMPLATE_SPECS]


@dataclass
class Candidate:
    template_id: int | None
    name: str
    transform_id: str
    alpha0: float
    beta0: float
    successes: int
    regressions: int
    provenance: str        # 'template' | 'fuzzy' | 'llm_cold'
    rendered_diff: str
    rationale: str = ""
    patch: object = None   # templates.RenderedPatch

    def posterior_mean(self) -> float:
        a = self.alpha0 + self.successes
        b = self.beta0 + self.regressions
        return a / (a + b)


def render(finding: Finding, transform_id: str, graph):
    try:
        return render_patch(transform_id, finding, graph)
    except (RenderError, SyntaxError, KeyError, IndexError):
        return None


def render_fix(finding: Finding, graph=None) -> str:
    """The rendered diff for a finding's own transform (empty if it can't render)."""
    if graph is None:
        from . import graph as graphmod
        graph = graphmod.build(finding.file_path)
    p = render(finding, finding.transform_id, graph)
    return p.diff if p else ""


def candidates_for(finding: Finding, stats: list[TemplateStat], graph,
                   provenance: str = "template", rationale: str = "") -> list[Candidate]:
    out: list[Candidate] = []
    for s in stats:
        patch = render(finding, s.transform_id, graph)
        if patch is None:
            continue
        out.append(Candidate(
            template_id=s.template_id, name=s.name, transform_id=s.transform_id,
            alpha0=s.alpha0, beta0=s.beta0, successes=s.successes,
            regressions=s.regressions, provenance=provenance,
            rendered_diff=patch.diff, rationale=rationale, patch=patch))
    return out


def llm_candidate(finding: Finding, provider, graph) -> Candidate | None:
    """Cold path: the provider picks a transform from the known vocabulary; the
    fix is rendered like any template. On verified success the orchestrator
    promotes it to an exact template."""
    proposal = provider.propose(finding)
    if proposal is None:
        return None
    patch = render(finding, proposal.transform_id, graph)
    if patch is None:
        return None
    return Candidate(
        template_id=None, name=f"llm:{provider.name}", transform_id=proposal.transform_id,
        alpha0=1.0, beta0=1.0, successes=0, regressions=0,
        provenance="llm_cold", rendered_diff=patch.diff,
        rationale=proposal.rationale, patch=patch)
