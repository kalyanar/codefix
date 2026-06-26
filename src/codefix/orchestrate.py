"""The loop: perceive -> detect -> fingerprint -> recall -> propose -> select
-> validate -> learn. One run over one app produces F1's data points.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from . import graph as graphmod
from . import detect, fingerprint, propose, learn
from .memory import PatchMemory
from .validate import verify
from .providers import resolve_provider
from .contrastive import enabled as contrastive_enabled


@dataclass
class IssueResult:
    func: str
    issue_class: str
    fp_hex: str
    provenance: str
    llm_used: bool
    template: str
    status: str
    detail: str
    warm: bool = False          # template recalled from DB had prior outcomes
    prior_successes: int = 0
    posterior: float = 0.5
    guard: str = ""             # the concrete fix rendered for THIS codebase
    stages: list = field(default_factory=list)   # validator stage results
    rendered_diff: str = ""     # full fix diff (for the PR)


@dataclass
class LoopEvent:
    phase: str          # perceive | detect | fingerprint | recall | propose | validate | learn
    target: str         # app or function
    detail: str


@dataclass
class RunReport:
    app: str
    results: list[IssueResult] = field(default_factory=list)
    events: list = field(default_factory=list)    # observable event stream (M11)

    @property
    def llm_rate(self) -> float:
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.llm_used) / len(self.results)

    @property
    def success_rate(self) -> float:
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.status == "success") / len(self.results)


def _ensure_templates(mem: PatchMemory, fp_id: int, issue_class: str):
    """Cold-start: if no template linked to this fingerprint, link the built-in
    ones for the class (auto-link with default prior)."""
    stats = mem.templates_for(fp_id, issue_class)
    if stats:
        return stats
    for t in propose.BUILTIN_TEMPLATES:
        if t["issue_class"] == issue_class:
            tid = mem.seed_template(t["name"], t["issue_class"], t["transform_id"])
            mem.link(tid, fp_id)
    return mem.templates_for(fp_id, issue_class)


DEFAULT_STRATEGIES = ("template", "fuzzy", "llm")
PRIOR_STRENGTH = 3.0   # pseudo-count: how strongly the bucket pattern informs a cold prior


def _hierarchical_prior(mem, key, fp_id):
    """Informative + hierarchical Beta prior (M8). A (fingerprint,template) arm's
    prior is drawn from its facet-bucket success rate, so a NEW/cold fingerprint
    inherits the pattern's wisdom (Beta(1,1) cold-start -> bucket-rate start)
    instead of a flat 0.5. greedy (posterior mean) and Thompson (posterior sample)
    use the SAME Beta, so the ablation is unconfounded."""
    bs, br = mem.bucket_stats(key, exclude_fp_id=fp_id)
    rate = (bs + 1) / (bs + br + 2)                 # smoothed bucket success rate
    return 1.0 + PRIOR_STRENGTH * rate, 1.0 + PRIOR_STRENGTH * (1 - rate)


def _strategy_candidates(strat, f, stats, provider):
    """Run one proposer strategy; return its candidates (empty if it yields none)."""
    if strat == "template":
        return propose.candidates_for(f, stats)
    if strat == "fuzzy":
        return []                                  # M9 (ANN/Hamming) — not in slice
    if strat == "llm":
        c = propose.llm_candidate(f, provider)
        return [c] if c else []
    return []


def run_once(app_dir: str, db_path: str, *, explore: bool = False, seed: int = 0,
             strategies=DEFAULT_STRATEGIES, provider: str = "mock",
             model: str | None = None, seed_builtin: bool = True,
             contrastive: bool | None = None, triage: bool = False) -> RunReport:
    app_dir = str(Path(app_dir).resolve())
    label = json.loads(Path(app_dir, "label.json").read_text())
    framework = label.get("framework", "none")
    exploit = str(Path(app_dir, "exploit.py"))
    legit = str(Path(app_dir, "legit.py"))

    g = graphmod.build(str(Path(app_dir, "app.py")))
    if triage:
        # NON-GATING: prioritize detector order from triage tags; recall unchanged
        from .triage import triage_tags, class_priority
        src = Path(app_dir, "app.py").read_text()
        findings, _ = detect.detect_prioritized(g, class_priority(triage_tags(src)))
    else:
        findings = detect.detect_all(g)

    mem = PatchMemory(db_path)
    rng = random.Random(seed)
    llm = resolve_provider(provider, model)
    report = RunReport(app=label.get("app", app_dir))

    def ev(phase, target, detail):
        report.events.append(LoopEvent(phase, target, detail))
    ev("perceive", report.app, f"{len(findings)} finding(s); framework={framework}")

    # M9 feature flag: train a contrastive embedder from verified-outcome pairs and
    # use it for fuzzy recall. OFF -> deterministic M7 embedding (ablatable).
    embedder = None
    if contrastive_enabled(contrastive):
        from .contrastive import ContrastiveEmbedder, mine_pairs, tokenize
        embedder = ContrastiveEmbedder()
        fp_facets = {r["id"]: (r["sink_category"], r["missing_guard_class"], r["framework"])
                     for r in mem.conn.execute(
                         "SELECT id, sink_category, missing_guard_class, framework FROM fingerprints")}
        tok_pairs = []
        for a, b, lab in mine_pairs(mem):
            if a in fp_facets and b in fp_facets:
                ta = tokenize("", *fp_facets[a])
                tb = tokenize("", *fp_facets[b])
                tok_pairs.append((ta, tb, lab))
        if tok_pairs:
            embedder.train(tok_pairs)

    for f in findings:
        key = fingerprint.compute(f, g, framework)
        fp_id = mem.upsert_fingerprint(key)
        stats = _ensure_templates(mem, fp_id, f.issue_class) if seed_builtin \
            else mem.templates_for(fp_id, f.issue_class)
        warm = any((s.successes + s.regressions) > 0 for s in stats)
        prior = max((s.successes for s in stats), default=0)

        # Fallback chain: try strategies in order; first to yield candidates wins.
        # Default order makes `template` primary and `llm` the fallback; flip the
        # order for LLM-first. The deterministic template path is always available.
        cands = []
        fuzzy_src_fp = None
        for strat in strategies:
            if strat == "fuzzy":
                fz = mem.fuzzy_lookup(key, embedder=embedder)
                if fz:
                    fuzzy_src_fp, nbr_templates, sim = fz
                    cands = [propose.Candidate(
                        template_id=s.template_id, name=s.name, transform_id=s.transform_id,
                        alpha0=s.alpha0, beta0=s.beta0, successes=s.successes,
                        regressions=s.regressions, provenance="fuzzy",
                        rendered_diff=propose.render_fix(f),
                        rationale=f"near-neighbor recall (cos={sim:.2f})")
                        for s in nbr_templates]
            else:
                cands = _strategy_candidates(strat, f, stats, llm)
            if cands:
                break

        if not cands:
            report.results.append(IssueResult(
                f.func, f.issue_class, key.hex(), "none", False, "-",
                "applied_no_tests", "no strategy produced a candidate",
                warm=warm, prior_successes=prior))
            continue

        # hierarchical prior: seed each arm's Beta prior from the facet bucket so
        # a cold fingerprint borrows the pattern's success rate (M8 patternise).
        prior_a, prior_b = _hierarchical_prior(mem, key, fp_id)
        for c in cands:
            if c.provenance in ("template", "fuzzy"):
                c.alpha0, c.beta0 = prior_a, prior_b

        ev("detect", f.func, f.issue_class)
        ev("fingerprint", f.func, key.hex())
        ev("recall", f.func, f"{cands[0].provenance} (warm={warm}, prior={prior})")

        chosen = learn.pick(cands, explore=explore, rng=rng)
        ev("propose", f.func, f"{chosen.name} [{chosen.provenance}]")
        verdict = verify(f, chosen, app_dir, exploit, legit)
        ev("validate", f.func, f"{verdict.status}: " +
           ",".join(f"{n}={'ok' if ok else 'FAIL'}" for n, ok in verdict.stages))

        # cold-path -> promote: a verified LLM fix becomes a template so the next
        # codebase with this fingerprint warm-starts without the LLM (F1 decline).
        template_id = chosen.template_id
        if chosen.provenance == "llm_cold" and verdict.status == "success":
            template_id = mem.seed_template(
                f"llm_synth::{f.issue_class}::{chosen.transform_id}",
                f.issue_class, chosen.transform_id)
            mem.link(template_id, fp_id)
        elif chosen.provenance == "fuzzy" and verdict.status == "success":
            # promote the neighbor's template to THIS fingerprint's exact row,
            # so next time the (framework-differing) variant is an exact hit
            mem.link(chosen.template_id, fp_id)

        pid = mem.record_patch(fp_id, template_id, chosen.provenance,
                               chosen.rendered_diff, "slice")
        signal = "exploit" if verdict.status in ("success", "regression") else "none"
        mem.record_outcome(pid, fp_id, template_id, verdict.status, signal)
        ev("learn", f.func, f"outcome={verdict.status}, posterior={chosen.posterior_mean():.3f}")

        report.results.append(IssueResult(
            f.func, f.issue_class, key.hex(), chosen.provenance,
            chosen.provenance == "llm_cold", chosen.name,
            verdict.status, verdict.detail,
            warm=warm, prior_successes=prior,
            posterior=chosen.posterior_mean(),
            guard=chosen.rendered_diff.strip().splitlines()[-2].strip().lstrip("+ "),
            stages=verdict.stages, rendered_diff=chosen.rendered_diff))

    mem.close()
    return report
