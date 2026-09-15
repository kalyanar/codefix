"""The loop (paper §III.A): Perceive -> (Triage) -> Detect, then per issue
Fingerprint -> Recall -> Select -> Act -> Validate -> Learn.

Every phase emits an event, so a run is a replayable trace. Only verified
outcomes (success / regression) touch PatchMemory; an unverified fix is never
applied, remembered or surfaced.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from . import graph as graphmod
from . import detect, fingerprint, propose, learn
from .memory import PatchMemory
from .validate import VERIFIED_STATUSES, verify
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
    warm: bool = False
    prior_successes: int = 0
    posterior: float = 0.5
    guard: str = ""
    stages: list = field(default_factory=list)
    rendered_diff: str = ""
    fp_label: str = ""
    missing_guard_class: str = ""
    finding: object = None
    patch: object = None
    applied: bool = False


@dataclass
class LoopEvent:
    phase: str
    target: str
    detail: str


@dataclass
class RunReport:
    app: str
    results: list[IssueResult] = field(default_factory=list)
    events: list = field(default_factory=list)
    findings: list = field(default_factory=list)

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
    stats = mem.templates_for(fp_id, issue_class)
    if stats:
        return stats
    for t in propose.BUILTIN_TEMPLATES:
        if t["issue_class"] == issue_class:
            tid = mem.seed_template(t["name"], t["issue_class"], t["transform_id"])
            mem.link(tid, fp_id)
    return mem.templates_for(fp_id, issue_class)


DEFAULT_STRATEGIES = ("template", "fuzzy", "llm")
PRIOR_STRENGTH = 3.0   # pseudo-count: how strongly the family bucket informs a cold prior


def _hierarchical_prior(mem, key, fp_id):
    """A cold fingerprint's Beta prior inherits its defect family's pooled rate
    (an empty family stays at 0.5). Greedy and Thompson read the same Beta."""
    bs, br = mem.bucket_stats(key, exclude_fp_id=fp_id)
    rate = (bs + 1) / (bs + br + 2)
    return 1.0 + PRIOR_STRENGTH * rate, 1.0 + PRIOR_STRENGTH * (1 - rate)


def _catalog_findings(mem, g, builtin_findings):
    """Admitted catalog specs run as data; a catalog finding never shadows a
    built-in one at the same location."""
    specs = mem.load_specs()
    if not specs:
        return [], 0
    claimed = {(f.fqname, f.sink_file, f.sink_lineno) for f in builtin_findings}
    extra = [f for f in detect.detect_registered(g, specs)
             if (f.fqname, f.sink_file, f.sink_lineno) not in claimed]
    return extra, len(specs)


def _harness_for(app_dir: Path, label: dict, finding) -> tuple[str, str, str]:
    base = app_dir / label.get("harness_root", "")
    for d in label.get("defects", []):
        fn = d.get("function")
        if fn and fn in (finding.func, finding.fqname) and \
                d.get("issue_class", finding.issue_class) == finding.issue_class:
            return (str(base / d.get("exploit", "exploit.py")),
                    str(base / d.get("legit", "legit.py")),
                    str(base / d.get("bypass", "bypass.py")))
    return (str(app_dir / "exploit.py"), str(app_dir / "legit.py"), str(app_dir / "bypass.py"))


def run_once(app_dir: str, db_path: str, *, explore: bool = False, seed: int = 0,
             strategies=DEFAULT_STRATEGIES, provider: str = "mock",
             model: str | None = None, seed_builtin: bool = True,
             contrastive: bool | None = None, triage: bool = False,
             catalog: bool = True, apply: bool = False, validate: bool = True,
             select: str | None = None) -> RunReport:
    app = Path(app_dir).resolve()
    label = {}
    for candidate in (app / ".codefix" / "codefix.json", app / "label.json"):
        if candidate.exists():
            label = json.loads(candidate.read_text())
            break
    mem = PatchMemory(db_path)
    report = RunReport(app=label.get("app", app.name))

    def ev(phase, target, detail):
        report.events.append(LoopEvent(phase, target, detail))

    g = graphmod.build(str(app), exclude=graphmod.harness_excluder)
    framework = label.get("framework") or g.framework()
    ev("perceive", report.app, f"{len(g.sources)} file(s), {len(g.functions)} function(s), "
       f"{len(g.edges)} call edge(s) in {g.build_seconds * 1000:.1f} ms; framework={framework}")

    if triage:
        from .triage import triage_tags, class_priority, explain
        tags = triage_tags(g.source)
        ev("triage", report.app, explain(tags))
        findings, _ = detect.detect_prioritized(g, class_priority(tags))
    else:
        findings = detect.detect_all(g)
    if catalog:
        extra, n_specs = _catalog_findings(mem, g, findings)
        if n_specs:
            ev("detect", report.app, f"catalog: {n_specs} admitted spec(s) -> {len(extra)} finding(s)")
        findings = findings + extra
    report.findings = findings

    codebase_id = mem.upsert_codebase(str(app), g.language, framework)
    applied_files: set = set()
    rng = random.Random(seed)
    llm = resolve_provider(provider, model)

    embedder = None
    if contrastive_enabled(contrastive):
        from .contrastive import ContrastiveEmbedder, mine_pairs, tokenize
        embedder = ContrastiveEmbedder()
        facets = {r["id"]: (r["sink_category"], r["missing_guard_class"], r["framework"])
                  for r in mem.conn.execute(
                      "SELECT id, sink_category, missing_guard_class, framework FROM fingerprints")}
        pairs = [(tokenize("", *facets[a]), tokenize("", *facets[b]), lab)
                 for a, b, lab in mine_pairs(mem) if a in facets and b in facets]
        if pairs:
            embedder.train(pairs)

    for f in findings:
        ev("detect", f.func, f"{f.issue_class} at {Path(f.sink_file).name}:{f.sink_lineno} "
           f"via {' -> '.join(lv.fqname.rsplit('.', 1)[-1] for lv in f.path)}")
        key = fingerprint.compute(f, g, framework)
        fp_id = mem.upsert_fingerprint(key)
        ev("fingerprint", f.func, f"{key.hex()} {fingerprint.label(key, f)}")
        issue_id = mem.record_issue(codebase_id, fp_id, f.issue_class,
                                    f"{Path(f.sink_file).relative_to(app) if Path(f.sink_file).is_relative_to(app) else f.sink_file}:{f.sink_lineno}:{f.func}")
        stats = _ensure_templates(mem, fp_id, f.issue_class) if seed_builtin \
            else mem.templates_for(fp_id, f.issue_class)
        warm = any((s.successes + s.regressions) > 0 for s in stats)
        prior = max((s.successes for s in stats), default=0)

        cands = []
        for strat in strategies:
            if strat == "template":
                cands = propose.candidates_for(f, stats, g)
            elif strat == "fuzzy":
                fz = mem.fuzzy_lookup(key, embedder=embedder)
                if fz:
                    _, nbr, sim = fz
                    cands = propose.candidates_for(f, nbr, g, provenance="fuzzy",
                                                   rationale=f"near-neighbour recall (cos={sim:.2f})")
            elif strat == "llm":
                c = propose.llm_candidate(f, llm, g)
                cands = [c] if c else []
            if cands:
                break
        if not cands:
            why = propose.RENDER_ERRORS[-1] if propose.RENDER_ERRORS else "no template matched"
            ev("recall", f.func, f"no strategy produced a candidate ({why})")
            report.results.append(IssueResult(
                f.func, f.issue_class, key.hex(), "none", False, "-", "unverified",
                "no strategy produced a candidate", warm=warm, prior_successes=prior,
                fp_label=fingerprint.label(key, f), missing_guard_class=f.missing_guard_class,
                finding=f))
            continue
        ev("recall", f.func, f"{cands[0].provenance} (warm={warm}, prior={prior})")

        prior_a, prior_b = _hierarchical_prior(mem, key, fp_id)
        for c in cands:
            if c.provenance in ("template", "fuzzy") and (c.successes + c.regressions) == 0:
                c.alpha0, c.beta0 = prior_a, prior_b

        mode = select or ("thompson" if explore else "greedy")
        chosen = learn.pick(cands, explore=(mode == "thompson"), rng=rng)
        ev("select", f.func, f"{mode}: {chosen.name} [{chosen.provenance}] "
           f"posterior={chosen.posterior_mean():.3f}")
        ev("propose", f.func, f"{chosen.name} [{chosen.provenance}]")
        ev("act", f.func, chosen.patch.guard)

        if not validate:
            report.results.append(IssueResult(
                f.func, f.issue_class, key.hex(), chosen.provenance,
                chosen.provenance == "llm_cold", chosen.name, "not_validated",
                "dry run: not validated", warm=warm, prior_successes=prior,
                posterior=chosen.posterior_mean(), guard=chosen.patch.guard,
                rendered_diff=chosen.rendered_diff, fp_label=fingerprint.label(key, f),
                missing_guard_class=f.missing_guard_class, finding=f, patch=chosen.patch))
            continue

        if apply and any(rel in applied_files for rel in chosen.patch.files):
            report.results.append(IssueResult(
                f.func, f.issue_class, key.hex(), chosen.provenance, False, chosen.name,
                "deferred", "file changed by an earlier fix this run; rescan", finding=f))
            continue
        exploit, legit, bypass = _harness_for(app, label, f)
        verdict = verify(f, chosen, str(app), exploit, legit, bypass, graph=g)
        ev("validate", f.func, f"{verdict.status}: " +
           ",".join(f"{n}={'ok' if ok else 'FAIL'}" for n, ok in verdict.stages))

        template_id = chosen.template_id
        if verdict.status in VERIFIED_STATUSES:
            if chosen.provenance == "llm_cold" and verdict.status == "success":
                template_id = mem.seed_template(
                    f"llm_synth::{f.issue_class}::{chosen.transform_id}",
                    f.issue_class, chosen.transform_id, origin="promoted_llm")
                mem.link(template_id, fp_id, prior_a, prior_b)
            elif chosen.provenance == "fuzzy" and verdict.status == "success":
                mem.link(chosen.template_id, fp_id, prior_a, prior_b)
            pid = mem.record_patch(issue_id, template_id, chosen.provenance, chosen.rendered_diff)
            mem.record_outcome(pid, verdict.status, "exploit", verdict.detail)
            ev("learn", f.func, f"outcome={verdict.status}, posterior={chosen.posterior_mean():.3f}")
        else:
            ev("learn", f.func, f"not learned: {verdict.status} ({verdict.detail})")

        applied = False
        if apply and verdict.status == "success":
            chosen.patch.write_to(str(app))
            applied_files.update(chosen.patch.files)
            applied = True
            ev("act", f.func, "applied to the codebase")

        report.results.append(IssueResult(
            f.func, f.issue_class, key.hex(), chosen.provenance,
            chosen.provenance == "llm_cold", chosen.name, verdict.status, verdict.detail,
            warm=warm, prior_successes=prior, posterior=chosen.posterior_mean(),
            guard=chosen.patch.guard, stages=verdict.stages,
            rendered_diff=chosen.rendered_diff, fp_label=fingerprint.label(key, f),
            missing_guard_class=f.missing_guard_class, finding=f, patch=chosen.patch,
            applied=applied))

    mem.close()
    return report
