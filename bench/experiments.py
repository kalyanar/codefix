"""M12 — corpus-scale experiments: the headline figures.

  F1  learning curve  : LLM-call rate falls as verified fixes fill the memory
  F2  transfer        : train on partition A, warm-start disjoint partition B
  Ablations           : greedy vs Thompson (regret), fuzzy on/off, triage on/off

All mechanisms are built + unit-tested (M1-M11); this runs them as a stream and
tabulates. Pure-Python ASCII plot (no matplotlib -> arch-independent). Writes
bench/experiment_results.json.

Usage: python bench/experiments.py
"""
import json
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from codefix.orchestrate import run_once  # noqa: E402

HERE = Path(__file__).resolve().parent
APPS = HERE / "apps"
COLD = dict(strategies=("template", "fuzzy", "llm"), provider="mock", seed_builtin=False)


def _run(app, db, **kw):
    return run_once(str(APPS / app), db, seed=0, **{**COLD, **kw}).results[0]


def sparkline(values, width=50):
    bars = "▁▂▃▄▅▆▇█"
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1
    pts = [values[int(i * (len(values) - 1) / (width - 1))] for i in range(width)]
    return "".join(bars[min(7, int((v - lo) / rng * 7))] for v in pts)


# --- F1: learning curve -------------------------------------------------------
def f1_learning_curve(tmpdb):
    Path(tmpdb).unlink(missing_ok=True)
    apps = ["shop_bola", "library_bola", "library_flat_bola", "admin_bfla",
            "mass_assign", "ssrf_preview", "missing_auth"]
    rng = random.Random(0)
    stream = []
    for _ in range(6):
        o = apps[:]; rng.shuffle(o); stream += o
    llm, succ = [], []
    for app in stream:
        r = _run(app, tmpdb)
        llm.append(1 if r.llm_used else 0)
        succ.append(1 if r.status == "success" else 0)
    cum_llm = [sum(llm[:i + 1]) / (i + 1) for i in range(len(llm))]
    cum_succ = [sum(succ[:i + 1]) / (i + 1) for i in range(len(succ))]
    return {"n": len(stream), "cum_llm_rate": cum_llm, "cum_success": cum_succ,
            "final_llm_rate": cum_llm[-1], "final_success": cum_succ[-1]}


# --- F2: transfer (train A, warm-start B) ------------------------------------
def f2_transfer(tmpdir):
    A = ["shop_bola", "admin_bfla", "mass_assign", "ssrf_preview", "missing_auth"]
    B = ["library_bola", "library_flat_bola"]
    # cold-start B (fresh memory)
    cold = str(Path(tmpdir, "cold.db")); Path(cold).unlink(missing_ok=True)
    cold_llm = sum(_run(app, cold).llm_used for app in B)
    # warm-start B (after training on A)
    warm = str(Path(tmpdir, "warm.db")); Path(warm).unlink(missing_ok=True)
    for app in A:
        _run(app, warm)
    warm_recall = [_run(app, warm) for app in B]
    warm_llm = sum(r.llm_used for r in warm_recall)
    warm_started = sum(1 for r in warm_recall if not r.llm_used and r.status == "success")
    return {"B_size": len(B), "cold_start_LLM_calls": cold_llm,
            "warm_start_LLM_calls": warm_llm, "warm_started_verified": warm_started}


# --- Ablation: greedy vs Thompson through codefix's own selector -----------------
def greedy_vs_thompson(seeds=30, N=200, pA=0.80, pB=0.45):
    """Selection ablation run through codefix's selector (`learn.pick`) over
    PatchMemory posteriors — greedy (posterior mean) and Thompson (posterior
    sample) read the SAME Beta rows in `template_fingerprint_links`.

    One BOLA fingerprint has two linked templates: the better one verifies with
    probability pA, the worse with pB. Adversarial cold start: the worse template
    is seeded with one early lucky success. Each round the chosen template's
    exploit-verification outcome is drawn from its true rate (the stochastic part
    stands in for varied codebases) and written back with `record_outcome`, which
    is what moves the posterior. Regret = pA - p(chosen), summed over N rounds."""
    import tempfile
    from codefix import learn, propose
    from codefix.fingerprint import FingerprintKey
    from codefix.memory import PatchMemory

    key = FingerprintKey("BOLA", "path_param", "object_read", "ownership", "handler", "flask")

    def sim(mode, seed):
        rng_sel, rng_env = random.Random(seed), random.Random(10_000 + seed)
        with tempfile.TemporaryDirectory() as d:
            mem = PatchMemory(":memory:")
            fp = mem.upsert_fingerprint(key)
            cb = mem.upsert_codebase(f"stream-{seed}")
            good = mem.seed_template("guard_after_fetch", "BOLA", "insert_ownership_guard")
            worse = mem.seed_template("guard_at_route_entry", "BOLA", "insert_ownership_guard")
            p_true = {good: pA, worse: pB}
            for t in (good, worse):
                mem.link(t, fp)
            issue = mem.record_issue(cb, fp, "BOLA", "seed")
            mem.record_outcome(mem.record_patch(issue, worse, "template", ""), "success", "exploit")
            regret = 0.0
            for i in range(N):
                cands = [propose.Candidate(t.template_id, t.name, t.transform_id, t.alpha0, t.beta0,
                                           t.successes, t.regressions, "template", "")
                         for t in mem.templates_for(fp, "BOLA")]
                chosen = learn.pick(cands, explore=(mode == "thompson"), rng=rng_sel)
                ok = rng_env.random() < p_true[chosen.template_id]
                issue = mem.record_issue(cb, fp, "BOLA", f"instance-{i}")
                pid = mem.record_patch(issue, chosen.template_id, "template", "")
                mem.record_outcome(pid, "success" if ok else "regression", "exploit")
                regret += pA - p_true[chosen.template_id]
            mem.close()
        return regret

    g = [sim("greedy", sd) for sd in range(seeds)]
    t = [sim("thompson", sd) for sd in range(seeds)]
    return {"greedy_regret_mean": statistics.mean(g), "thompson_regret_mean": statistics.mean(t),
            "greedy_regret_max": max(g), "thompson_regret_max": max(t),
            "seeds": seeds, "rounds": N, "pA": pA, "pB": pB}


# --- Triage (non-gating) -------------------------------------------------------
def triage_study():
    """Cost-to-first (1-based detector position of the first hit) with and without
    triage, recall compared against the full sweep, plus a deliberately wrong tag set."""
    from codefix import detect, graph, triage
    rows = []
    for app in ("shop_bola", "admin_bfla", "mass_assign", "ssrf_preview", "missing_auth"):
        g = graph.build(str(APPS / app), exclude=graph.harness_excluder)
        full, c_full = detect.detect_prioritized(g, detect.ALL_CLASSES)
        tri, c_tri = detect.detect_prioritized(g, triage.class_priority(triage.triage_tags(g.source)))
        rows.append({"app": app, "cost_full": c_full, "cost_triage": c_tri,
                     "recall_equal": sorted((f.issue_class, f.func) for f in full) ==
                     sorted((f.issue_class, f.func) for f in tri)})
    g = graph.build(str(APPS / "ssrf_preview"), exclude=graph.harness_excluder)
    wrong, _ = detect.detect_prioritized(g, ["BOLA", "BFLA", "MASS_ASSIGNMENT"])
    return {"rows": rows, "max_cost_full": max(r["cost_full"] for r in rows),
            "max_cost_triage": max(r["cost_triage"] for r in rows),
            "all_recall_equal": all(r["recall_equal"] for r in rows),
            "wrong_tags_still_find_ssrf": any(f.issue_class == "SSRF" for f in wrong)}


# --- Contrastive feature learning -------------------------------------------------
def contrastive_study(tmpdir):
    """Train the (feature-flagged) contrastive embedder from outcome-labelled pairs.
    The transferred pair is mined from PatchMemory after real verified runs (the
    same template verified on the framework=none and framework=fastapi BOLA); the
    regressed pair is the nested-context case, labelled -1."""
    from codefix.contrastive import ContrastiveEmbedder, mine_pairs, tokenize
    from codefix.memory import PatchMemory
    db = str(Path(tmpdir, "contrastive.db")); Path(db).unlink(missing_ok=True)
    run_once(str(APPS / "library_bola"), db, seed=0, seed_builtin=True)
    run_once(str(APPS / "library_bola_fastapi"), db, seed=0, seed_builtin=True)
    mem = PatchMemory(db)
    facets = {r["id"]: r for r in mem.conn.execute("SELECT * FROM fingerprints")}
    mined = [(a, b, lab) for a, b, lab in mine_pairs(mem) if lab > 0]
    mem.close()
    a, b, _ = mined[0]
    ta = tokenize(facets[a]["issue_class"], facets[a]["sink_category"],
                  facets[a]["missing_guard_class"], framework=facets[a]["framework"])
    tb = tokenize(facets[b]["issue_class"], facets[b]["sink_category"],
                  facets[b]["missing_guard_class"], framework=facets[b]["framework"])
    base = tokenize("BOLA", "object_read", "ownership")
    nested = tokenize("BOLA", "object_read", "ownership", context="nested")
    e = ContrastiveEmbedder()
    before = (e.cosine(ta, tb), e.cosine(base, nested))
    e.train([(ta, tb, +1), (base, nested, -1)], epochs=40)
    return {"mined_transferred_pair": [facets[a]["framework"], facets[b]["framework"]],
            "cos_before": [round(x, 3) for x in before],
            "cos_transferred": round(e.cosine(ta, tb), 3),
            "cos_regressed": round(e.cosine(base, nested), 3),
            "weights": {k: round(v, 3) for k, v in sorted(e.w.items())}}


# --- CodeMap build time ------------------------------------------------------------
def build_time_study(repeats=20):
    from codefix import graph
    out = []
    for name, path in (("VAmPI", APPS / "vampi" / "vendor"),
                       ("crAPI workshop", APPS / "crapi" / "vendor"),
                       ("pygoat", APPS / "pygoat" / "vendor")):
        if not path.exists():
            continue
        times = []
        for _ in range(repeats):
            g = graph.build(str(path), exclude=graph.harness_excluder)
            times.append(g.build_seconds * 1000)
        out.append({"repo": name, "files": len(g.sources), "functions": len(g.functions),
                    "edges": len(g.edges), "median_ms": round(statistics.median(times), 1)})
    return out


# --- Ablation: fuzzy on/off, triage on/off -----------------------------------
def fuzzy_ablation(tmpdir):
    # train BOLA (framework none); then a different-framework BOLA variant
    def trial(use_fuzzy):
        db = str(Path(tmpdir, f"fz_{use_fuzzy}.db")); Path(db).unlink(missing_ok=True)
        run_once(str(APPS / "library_bola"), db, seed=0, seed_builtin=True)
        strat = ("template", "fuzzy", "llm") if use_fuzzy else ("template", "llm")
        r = run_once(str(APPS / "library_bola_fastapi"), db, seed=0,
                     strategies=strat, provider="mock", seed_builtin=False).results[0]
        return r.provenance, r.llm_used
    on = trial(True); off = trial(False)
    return {"fuzzy_on": {"provenance": on[0], "llm_used": on[1]},
            "fuzzy_off": {"provenance": off[0], "llm_used": off[1]}}


def main():
    import tempfile
    tmp = tempfile.mkdtemp()
    f1 = f1_learning_curve(str(Path(tmp, "f1.db")))
    f2 = f2_transfer(tmp)
    gt = greedy_vs_thompson()
    fz = fuzzy_ablation(tmp)
    tr = triage_study()
    ct = contrastive_study(tmp)
    bt = build_time_study()

    print("=" * 64)
    print("F1 — LEARNING CURVE (LLM-call rate over a corpus stream, cold start)")
    print(f"  issues: {f1['n']}   cumulative LLM-call rate:")
    print(f"    1.0 |{sparkline(f1['cum_llm_rate'])}| {f1['final_llm_rate']:.2f}")
    print(f"  exploit-verified success rate (final): {f1['final_success']:.2f}")

    print("\n" + "=" * 64)
    print("F2 — TRANSFER (train partition A, warm-start disjoint partition B)")
    print(f"  cold-start LLM calls on B: {f2['cold_start_LLM_calls']}   warm-start: "
          f"{f2['warm_start_LLM_calls']}   warm-started + verified: "
          f"{f2['warm_started_verified']}/{f2['B_size']}")

    print("\n" + "=" * 64)
    print(f"SELECTION — greedy vs Thompson via codefix's selector + PatchMemory "
          f"(adversarial cold start, pA={gt['pA']}, pB={gt['pB']}, {gt['rounds']} rounds, "
          f"{gt['seeds']} seeds)")
    print(f"  greedy   regret: mean {gt['greedy_regret_mean']:5.1f}   WORST-CASE {gt['greedy_regret_max']:5.1f}")
    print(f"  thompson regret: mean {gt['thompson_regret_mean']:5.1f}   WORST-CASE {gt['thompson_regret_max']:5.1f}")

    print("\n" + "=" * 64)
    print("FUZZY recall on/off (different-framework BOLA variant)")
    print(f"  on : {fz['fuzzy_on']}   off: {fz['fuzzy_off']}")

    print("\n" + "=" * 64)
    print("TRIAGE (non-gating)")
    for r in tr["rows"]:
        print(f"  {r['app']:14} cost-to-first full={r['cost_full']} triage={r['cost_triage']} "
              f"recall_equal={r['recall_equal']}")
    print(f"  worst cost-to-first: {tr['max_cost_full']} -> {tr['max_cost_triage']}; "
          f"wrong tags still find SSRF: {tr['wrong_tags_still_find_ssrf']}")

    print("\n" + "=" * 64)
    print("CONTRASTIVE (feature-flagged)")
    print(f"  transferred pair (mined, frameworks {ct['mined_transferred_pair']}): cos -> "
          f"{ct['cos_transferred']}   regressed nested-context pair: cos -> {ct['cos_regressed']}")
    print(f"  learned weights: {ct['weights']}")

    print("\n" + "=" * 64)
    print("CODEMAP build time (median over 20 builds)")
    for b in bt:
        print(f"  {b['repo']:15} {b['files']:3} files {b['functions']:4} functions "
              f"{b['edges']:5} edges  {b['median_ms']} ms")

    out = {"F1": f1, "F2": f2, "greedy_vs_thompson": gt, "fuzzy_ablation": fz,
           "triage": tr, "contrastive": ct, "build_time": bt}
    (HERE / "experiment_results.json").write_text(json.dumps(out, indent=2))
    print(f"\nwrote {HERE / 'experiment_results.json'}")


if __name__ == "__main__":
    main()
