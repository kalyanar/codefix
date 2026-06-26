"""Regression tests for the vertical slice.

These encode the claims the slice exists to prove:
  - the full loop is exploit-verified (success only when the exploit is blocked
    AND the legitimate path is preserved);
  - detection is name-independent (renamed identifiers still caught; a guard in
    a differently-named helper still recognised).
"""
import textwrap
from pathlib import Path

from codefix import graph, detect
from codefix.orchestrate import run_once

BENCH = Path(__file__).resolve().parents[1] / "bench" / "apps" / "shop_bola"


def _write_app(tmp_path, src: str):
    d = tmp_path / "app"
    d.mkdir()
    (d / "app.py").write_text(textwrap.dedent(src))
    return str(d / "app.py")


def test_end_to_end_exploit_verified(tmp_path):
    db = str(tmp_path / "m.db")
    rep = run_once(str(BENCH), db, explore=False, seed=0)
    assert len(rep.results) == 1
    r = rep.results[0]
    assert r.issue_class == "BOLA"
    assert r.status == "success"          # exploit blocked + legit preserved
    assert rep.llm_rate == 0.0            # template used, no LLM
    assert rep.success_rate == 1.0


def test_detection_survives_renaming(tmp_path):
    src = """
        ORDERS = {1: {"id": 1, "user_id": 1}}
        _CURRENT = {"uid": None}
        def login(uid): _CURRENT["uid"] = uid
        def current_user_id(): return _CURRENT["uid"]
        def fetch_thing(q7): return ORDERS.get(q7)
        def handler(q7):
            x = fetch_thing(q7)
            return x
    """
    g = graph.build(_write_app(tmp_path, src))
    findings = detect.detect_bola(g)
    assert [f.func for f in findings] == ["handler"]


def test_guard_in_differently_named_helper_is_not_flagged(tmp_path):
    src = """
        ORDERS = {1: {"id": 1, "user_id": 1}}
        _CURRENT = {"uid": None}
        def login(uid): _CURRENT["uid"] = uid
        def current_user_id(): return _CURRENT["uid"]
        def get_order_by_id(order_id): return ORDERS.get(order_id)
        def gate(obj):
            if obj is not None and obj["user_id"] != current_user_id():
                raise PermissionError("nope")
        def get_order(order_id):
            order = get_order_by_id(order_id)
            gate(order)
            return order
    """
    g = graph.build(_write_app(tmp_path, src))
    findings = detect.detect_bola(g)
    assert findings == []                 # principal-comparison shape recognised


def test_facet_fingerprint_is_structure_invariant(tmp_path):
    """Nested and flat versions of the same defect share a fingerprint, so the
    store does not grow or change for structural variation."""
    from codefix import graph, detect, fingerprint
    nested = graph.build(str(BENCH.parent / "library_bola" / "app.py"))
    flat = graph.build(str(BENCH.parent / "library_flat_bola" / "app.py"))
    fn, ff = detect.detect_all(nested)[0], detect.detect_all(flat)[0]
    # structurally different...
    assert len(nested.callees(fn.func, depth=1)) != len(flat.callees(ff.func, depth=1))
    # ...same facet fingerprint
    assert fingerprint.compute(fn, nested, "none").hex() == \
           fingerprint.compute(ff, flat, "none").hex()


def test_store_invariant_to_structure(tmp_path):
    import sqlite3
    db = str(tmp_path / "s.db")
    for app in ("shop_bola", "library_bola", "library_flat_bola"):
        run_once(str(BENCH.parent / app), db, seed=0)
    c = sqlite3.connect(db)
    rows = c.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
    succ = c.execute("SELECT successes FROM links").fetchone()[0]
    assert rows == 1          # one row for 3 different-structure apps
    assert succ == 3          # all fed the same posterior


def test_structural_transfer_warm_start(tmp_path):
    db = str(tmp_path / "t.db")
    run_once(str(BENCH.parent / "library_bola"), db, seed=0)       # nested, learns
    rb = run_once(str(BENCH.parent / "library_flat_bola"), db, seed=0)  # flat, transfers
    r = rb.results[0]
    assert r.warm and not r.llm_used and r.status == "success"


def test_coldpath_llm_promotes_to_template(tmp_path):
    """LLM strategy fires when no template exists, gets exploit-verified, is
    promoted to a template; the next codebase warm-starts without the LLM."""
    db = str(tmp_path / "c.db")
    ra = run_once(str(BENCH.parent / "shop_bola"), db, seed=0,
                  strategies=("template", "llm"), provider="mock", seed_builtin=False)
    rb = run_once(str(BENCH.parent / "library_bola"), db, seed=0,
                  strategies=("template", "llm"), provider="mock", seed_builtin=False)
    a, b = ra.results[0], rb.results[0]
    assert a.provenance == "llm_cold" and a.status == "success"   # LLM proposed + verified
    assert b.provenance == "template" and not b.llm_used          # warm from promoted template
    assert b.status == "success"
    assert ra.llm_rate == 1.0 and rb.llm_rate == 0.0              # LLM-rate declines


def test_authoring_gate_admits_valid_and_rejects_bad(tmp_path):
    from codefix.detect import DetectorSpec
    from codefix.authoring import run_gate
    fx = str(BENCH.parent / "new_issue_idor_note")
    good = DetectorSpec("IDOR_NOTE", "param_to_sink", "insert_ownership_guard",
                        "param", "data_access_by_id", "ownership", "sink_local")
    assert run_gate(good, fx).admitted                          # valid spec admitted
    bad_enum = DetectorSpec("IDOR_NOTE", "param_to_sink", "insert_ownership_guard",
                            "param", "data_access_by_id", "owner_check", "sink_local")
    assert not run_gate(bad_enum, fx).admitted                  # off-vocabulary -> rejected
    bad_flow = DetectorSpec("IDOR_NOTE", "privileged_op", "insert_role_guard_at_start",
                            "param", "privileged_mutation", "role", "entry_local")
    assert not run_gate(bad_flow, fx).admitted                  # can't detect planted vuln


def test_full_validator_stack(tmp_path):
    """shop_bola fix passes all 4 validator stages."""
    from codefix import graph, detect, propose
    from codefix.validate import verify
    from codefix.propose import Candidate
    g = graph.build(str(BENCH / "app.py"))
    f = detect.detect_all(g)[0]
    c = Candidate(template_id=None, name="t", transform_id=f.transform_id,
                  alpha0=1, beta0=1, successes=0, regressions=0,
                  provenance="template", rendered_diff=propose.render_fix(f))
    v = verify(f, c, str(BENCH), str(BENCH / "exploit.py"), str(BENCH / "legit.py"))
    names = {n for n, ok in v.stages}
    assert v.status == "success"
    assert names == {"exploit-blocked", "differential-legit",
                     "contract-conformance", "adversarial-bypass"}
    assert all(ok for _, ok in v.stages)


def test_adversarial_bypass_catches_overfit(tmp_path):
    """An overfit guard (blocks only one victim) is caught by adversarial-bypass."""
    import shutil, subprocess, sys
    d = tmp_path / "app"
    shutil.copytree(str(BENCH), d)
    p = d / "app.py"
    lines = p.read_text().splitlines(keepends=True)
    for i, l in enumerate(lines):
        if "get_order_by_id(order_id)" in l and "def " not in l:
            ind = l[: len(l) - len(l.lstrip())]
            lines.insert(i + 1, f'{ind}if order is not None and order["user_id"] == 2 '
                                f'and current_user_id() != 2:\n{ind}    raise PermissionError("x")\n')
            break
    p.write_text("".join(lines))
    rc = subprocess.run([sys.executable, str(BENCH / "bypass.py"), "--app", str(d)],
                        capture_output=True, text=True).returncode
    assert rc != 0          # bypass succeeded -> caught the overfit fix


# --- M3: def-use taint propagation + branch-sensitive dominance ---
import textwrap as _tw

_PRE = """
NOTES={1:{"id":1,"user_id":1},2:{"id":2,"user_id":2}}
_C={"u":None}
def login(u): _C["u"]=u
def current_user_id(): return _C["u"]
def get_order_by_id(i): return NOTES.get(i)
"""

def _detect_src(tmp_path, body):
    from codefix import graph, detect
    p = tmp_path / "app.py"; p.write_text(_tw.dedent(_PRE + body))
    return detect.detect_all(graph.build(str(p)))

def test_m3_taint_through_assignment_chain(tmp_path):
    # param threaded through oid->key into the sink; direct-ref check would miss it
    fs = _detect_src(tmp_path, """
def get_order(order_id):
    oid = order_id
    key = oid
    order = get_order_by_id(key)
    return order
""")
    assert len(fs) == 1 and fs[0].issue_class == "BOLA"

def test_m3_guard_in_skippable_branch_still_vulnerable(tmp_path):
    fs = _detect_src(tmp_path, """
def get_order(order_id, flag):
    order = get_order_by_id(order_id)
    if flag:
        if order["user_id"] != current_user_id():
            raise PermissionError("x")
    return order
""")
    assert len(fs) == 1                      # guard doesn't dominate -> still flagged

def test_m3_non_denying_check_is_not_a_guard(tmp_path):
    fs = _detect_src(tmp_path, """
def get_order(order_id):
    order = get_order_by_id(order_id)
    if order["user_id"] != current_user_id():
        pass
    return order
""")
    assert len(fs) == 1                      # no raise/return -> not a guard

def test_m3_proper_dominating_guard_is_clean(tmp_path):
    fs = _detect_src(tmp_path, """
def get_order(order_id):
    order = get_order_by_id(order_id)
    if order["user_id"] != current_user_id():
        raise PermissionError("x")
    return order
""")
    assert fs == []                          # top-level denial guard -> mitigated


def test_m4_mass_assignment_end_to_end(tmp_path):
    """Mass assignment (3rd class) detected via **kwargs sink, fixed with an
    allowlist, exploit-verified; no collision with BOLA/BFLA."""
    from codefix import graph, detect
    db = str(tmp_path / "ma.db")
    # detection is class-specific (no collision)
    ma = detect.detect_all(graph.build(str(BENCH.parent / "mass_assign" / "app.py")))
    assert [f.issue_class for f in ma] == ["MASS_ASSIGNMENT"]
    bola = detect.detect_all(graph.build(str(BENCH / "app.py")))
    assert [f.issue_class for f in bola] == ["BOLA"]
    # full loop exploit-verified
    rep = run_once(str(BENCH.parent / "mass_assign"), db, seed=0)
    assert rep.results[0].status == "success"


def test_m4_five_authz_classes_no_collision(tmp_path):
    """All 5 authz-family classes detect on their own fixture, exactly one each."""
    from codefix import graph, detect
    expect = {"shop_bola": "BOLA", "admin_bfla": "BFLA", "mass_assign": "MASS_ASSIGNMENT",
              "ssrf_preview": "SSRF", "missing_auth": "MISSING_AUTH"}
    for app, cls in expect.items():
        fs = detect.detect_all(graph.build(str(BENCH.parent / app / "app.py")))
        assert [f.issue_class for f in fs] == [cls], f"{app}: {[f.issue_class for f in fs]}"


def test_m4_ssrf_exploit_verified(tmp_path):
    rep = run_once(str(BENCH.parent / "ssrf_preview"), str(tmp_path / "s.db"), seed=0)
    assert rep.results[0].issue_class == "SSRF" and rep.results[0].status == "success"


def test_m4_missing_auth_exploit_verified(tmp_path):
    rep = run_once(str(BENCH.parent / "missing_auth"), str(tmp_path / "m.db"), seed=0)
    assert rep.results[0].issue_class == "MISSING_AUTH" and rep.results[0].status == "success"


def test_m7_fuzzy_recall_on_exact_miss(tmp_path):
    """Same defect, different framework -> exact key misses; fuzzy near-neighbor
    recall borrows the fix (no LLM), exploit-verifies it, and promotes it to the
    new fingerprint's exact row."""
    import sqlite3
    db = str(tmp_path / "fz.db")
    a = run_once(str(BENCH.parent / "library_bola"), db, seed=0, seed_builtin=True)
    b = run_once(str(BENCH.parent / "library_bola_fastapi"), db, seed=0,
                 strategies=("template", "fuzzy", "llm"), provider="mock", seed_builtin=False)
    ra, rb = a.results[0], b.results[0]
    assert ra.fp_hex != rb.fp_hex            # exact keys differ (framework)
    assert rb.provenance == "fuzzy"          # recalled via near-neighbor
    assert not rb.llm_used                   # no LLM needed
    assert rb.status == "success"            # exploit-verified
    c = sqlite3.connect(db)
    promoted = c.execute(
        "SELECT COUNT(*) FROM links l JOIN fingerprints f ON f.id=l.fingerprint_id"
        " WHERE f.framework='fastapi'").fetchone()[0]
    assert promoted > 0                      # promoted to exact for next time


def test_m8_hierarchical_prior_patternise(tmp_path):
    """A cold fingerprint borrows its prior from the facet-bucket pattern; a
    fingerprint with an empty bucket stays at the flat 0.5."""
    from codefix.orchestrate import run_once, _hierarchical_prior
    from codefix.memory import PatchMemory
    from codefix import graph, detect, fingerprint
    from codefix.fingerprint import FingerprintKey
    db = str(tmp_path / "m8.db")
    run_once(str(BENCH), db, seed=0, seed_builtin=True)               # BOLA success
    run_once(str(BENCH.parent / "library_bola"), db, seed=0, seed_builtin=True)
    mem = PatchMemory(db)
    g = graph.build(str(BENCH.parent / "library_bola_fastapi" / "app.py"))
    key = fingerprint.compute(detect.detect_all(g)[0], g, "fastapi")
    fp = mem.upsert_fingerprint(key)
    pa, pb = _hierarchical_prior(mem, key, fp)
    assert pa / (pa + pb) > 0.5                                       # inherits the pattern
    ek = FingerprintKey("SSRF", "param", "url_fetch", "url_validation", "sink_local", "none")
    fe = mem.upsert_fingerprint(ek)
    pa2, pb2 = _hierarchical_prior(mem, ek, fe)
    assert abs(pa2 / (pa2 + pb2) - 0.5) < 1e-9                        # empty bucket -> flat


def test_m9_contrastive_separates_regressed_pair(tmp_path):
    """The embedder learns: a transferred pair stays close, a regressed pair is
    pushed apart — feature relevance learned from outcome labels."""
    from codefix.contrastive import ContrastiveEmbedder, tokenize
    flask = tokenize("BOLA", "dar", "own", framework="flask")
    fastapi = tokenize("BOLA", "dar", "own", framework="fastapi")
    base = tokenize("BOLA", "dar", "own")
    nested = tokenize("BOLA", "dar", "own", context="nested")
    e = ContrastiveEmbedder()
    e.train([(flask, fastapi, +1), (base, nested, -1)], epochs=40)
    assert e.cosine(flask, fastapi) >= 0.95     # transferred pair: close
    assert e.cosine(base, nested) < 0.95        # regressed pair: pushed apart


def test_m9_feature_flag_off_by_default(tmp_path):
    """Flag OFF (default) = deterministic M7; flag ON still runs (graceful)."""
    from codefix.contrastive import enabled
    assert enabled() is False                   # default off
    assert enabled(False) is False and enabled(True) is True
    # both flag states run end-to-end without error
    for flag in (False, True):
        rep = run_once(str(BENCH), str(tmp_path / f"f{flag}.db"), seed=0, contrastive=flag)
        assert rep.results[0].status == "success"


def _fset(fs):
    return sorted((f.issue_class, f.func) for f in fs)

def test_m10_triage_equal_recall_lower_cost(tmp_path):
    """Triage cuts cost-to-first to 1 while recall is identical to the full sweep."""
    from codefix import graph, detect, triage
    g = graph.build(str(BENCH.parent / "ssrf_preview" / "app.py"))
    src = (BENCH.parent / "ssrf_preview" / "app.py").read_text()
    full, full_cost = detect.detect_prioritized(g, detect.ALL_CLASSES)
    tri, tri_cost = detect.detect_prioritized(g, triage.class_priority(triage.triage_tags(src)))
    assert _fset(full) == _fset(tri)            # equal recall
    assert tri_cost == 1 and full_cost > 1      # found sooner

def test_m10_triage_is_non_gating(tmp_path):
    """Even WRONG triage tags cannot cause a miss (priority is always a full set)."""
    from codefix import graph, detect
    g = graph.build(str(BENCH.parent / "ssrf_preview" / "app.py"))
    full, _ = detect.detect_prioritized(g, detect.ALL_CLASSES)
    wrong, _ = detect.detect_prioritized(g, ["BOLA", "BFLA", "MASS_ASSIGNMENT"])  # SSRF omitted
    assert _fset(full) == _fset(wrong)          # SSRF still found

def test_m10_triage_flag_preserves_results(tmp_path):
    """run_once with triage on/off yields the same verdict (non-gating end-to-end)."""
    a = run_once(str(BENCH.parent / "ssrf_preview"), str(tmp_path / "a.db"), seed=0, triage=False)
    b = run_once(str(BENCH.parent / "ssrf_preview"), str(tmp_path / "b.db"), seed=0, triage=True)
    assert _fset_r(a) == _fset_r(b)

def _fset_r(rep):
    return sorted((r.issue_class, r.func, r.status) for r in rep.results)


def test_m11_event_stream(tmp_path):
    """The loop emits an observable event for every phase."""
    rep = run_once(str(BENCH), str(tmp_path / "e.db"), seed=0)
    phases = [e.phase for e in rep.events]
    for p in ("perceive", "detect", "fingerprint", "recall", "propose", "validate", "learn"):
        assert p in phases, f"missing phase {p}"

def test_m11_pr_output(tmp_path):
    """A verified fix yields a PR draft with the exploit evidence; unverified -> None."""
    from codefix.pr import make_pr_draft
    rep = run_once(str(BENCH), str(tmp_path / "p.db"), seed=0)
    draft = make_pr_draft(rep.app, rep.results[0])
    assert draft is not None
    assert "fix(security): BOLA" in draft.title
    assert "Exploit-verified evidence" in draft.body
    assert "[x] exploit-blocked" in draft.body
    assert "```diff" in draft.body
    # an unverified result produces no PR
    from dataclasses import replace
    bad = replace(rep.results[0], status="regression")
    assert make_pr_draft(rep.app, bad) is None


def test_m12_experiment_figures(tmp_path):
    """The headline figures hold: F1 LLM-rate declines, F2 transfers, Thompson
    beats greedy on regret, fuzzy avoids the cold-path."""
    import sys
    sys.path.insert(0, str(BENCH.parents[1]))
    import experiments as X
    f1 = X.f1_learning_curve(str(tmp_path / "f1.db"))
    assert f1["cum_llm_rate"][-1] < f1["cum_llm_rate"][0]      # F1 declines
    assert f1["final_success"] == 1.0                          # all fixes verified
    f2 = X.f2_transfer(str(tmp_path))
    assert f2["warm_start_LLM_calls"] < f2["cold_start_LLM_calls"]   # F2 transfer
    assert f2["warm_started_verified"] == f2["B_size"]
    gt = X.greedy_vs_thompson(seeds=30, N=200)
    # the honest Thompson advantage is the TAIL: greedy can lock onto the worse
    # arm (catastrophic worst case); Thompson bounds it
    assert gt["thompson_regret_max"] < gt["greedy_regret_max"]
    fz = X.fuzzy_ablation(str(tmp_path))
    assert fz["fuzzy_on"]["llm_used"] is False and fz["fuzzy_off"]["llm_used"] is True


def test_m13_extensible_catalog_lifecycle(tmp_path):
    """Propose -> gate -> persist -> (fresh instance) load -> run. A new class is
    added as gated+persisted data, with no engine code change. Bad specs aren't
    persisted."""
    from codefix.memory import PatchMemory
    from codefix.detect import DetectorSpec
    from codefix.authoring import admit_if_passes
    from codefix import graph, detect
    fx = str(BENCH.parent / "new_issue_idor_note")
    db = str(tmp_path / "cat.db")
    assert "IDOR_NOTE" not in detect.ALL_CLASSES               # not a built-in

    good = DetectorSpec("IDOR_NOTE", "param_to_sink", "insert_ownership_guard",
                        "param", "data_access_by_id", "ownership", "sink_local")
    m1 = PatchMemory(db)
    assert admit_if_passes(good, fx, m1).admitted               # gate passes -> persisted
    m1.close()

    m2 = PatchMemory(db)                                        # fresh instance
    specs = m2.load_specs()
    assert [s.issue_class for s in specs] == ["IDOR_NOTE"]      # persisted across runs
    g = graph.build(fx + "/vuln/app.py")
    found = detect.detect_registered(g, specs)
    assert [(f.issue_class, f.func) for f in found] == [("IDOR_NOTE", "read_note")]

    # a bad (off-vocabulary) spec is rejected and NOT persisted
    bad = DetectorSpec("IDOR_NOTE", "param_to_sink", "insert_ownership_guard",
                       "param", "data_access_by_id", "owner_check", "sink_local")
    m3 = PatchMemory(str(tmp_path / "cat2.db"))
    assert not admit_if_passes(bad, fx, m3).admitted
    assert m3.load_specs() == []
