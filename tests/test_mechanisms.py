"""Tests for the mechanisms the paper describes beyond the original slice:
cross-file CodeMap, dominance over a real CFG, bidirectional bounded search,
library-symbol sinks, rendering from the target AST, the mandatory four-stage
validator, and the eight-table PatchMemory."""
import sqlite3
import textwrap
import time
from pathlib import Path

import pytest

from codefix import detect, fingerprint, graph
from codefix.orchestrate import run_once

APPS = Path(__file__).resolve().parents[1] / "bench" / "apps"


def _pkg(tmp_path, files: dict) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return tmp_path


def _classes(root):
    return [(f.issue_class, f.func) for f in detect.detect_all(graph.build(str(root)))]


# --- §III.B CodeMap -------------------------------------------------------------

def test_codemap_three_pass_cross_file(tmp_path):
    root = _pkg(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/auth.py": """
            def guard(fn):
                def wrapper(*a, **k):
                    return fn(*a, **k)
                return wrapper
        """,
        "pkg/svc/__init__.py": "",
        "pkg/svc/core.py": """
            import requests
            from ..auth import guard

            class Repo:
                def load(self, i):
                    return self.fetch(i)
                def fetch(self, i):
                    return requests.get(i)

            @guard
            def handler(x):
                y = x
                return Repo().load(y)
        """,
    })
    g = graph.build(str(root))
    assert {"pkg.svc.core.Repo.load", "pkg.svc.core.Repo.fetch", "pkg.svc.core.handler",
            "pkg.auth.guard", "pkg.auth.guard.wrapper"} <= set(g.functions)
    fn = g.functions["pkg.svc.core.Repo.load"]
    assert fn.parent_class == "Repo" and fn.file.endswith("core.py") and fn.end_lineno > fn.lineno
    edges = {(e.caller, e.callee_name): e for e in g.edges}
    assert edges[("pkg.svc.core.Repo.load", "self.fetch")].callee_fqname == "pkg.svc.core.Repo.fetch"
    ext = edges[("pkg.svc.core.Repo.fetch", "requests.get")]
    assert ext.callee_fqname is None and ext.callee_symbol == "requests.get"   # unresolved, kept
    assert g.imports["pkg.svc.core"]["guard"] == "pkg.auth.guard"               # relative import
    assert any(d.func == "pkg.svc.core.handler" and d.decorator_fqname == "pkg.auth.guard"
               for d in g.decorator_edges)
    assert any(e.func == "pkg.svc.core.handler" and (e.target, e.source) == ("y", "x")
               for e in g.defuse)


def test_codemap_build_time_is_recorded(tmp_path):
    files = {"big/__init__.py": ""}
    for i in range(40):
        files[f"big/m{i}.py"] = "\n".join(
            [f"from .m{(i + 1) % 40} import f0 as nxt"] +
            [f"def f{j}(a, b):\n    c = a + b\n    return nxt(c, b) if c else f{(j + 1) % 8}(b, a)\n"
             for j in range(8)])
    g = graph.build(str(_pkg(tmp_path, files)))
    assert len(g.sources) == 41 and len(g.functions) == 320
    assert g.build_seconds < 0.5          # the measured figure is reported by bench/experiments.py


def test_bola_across_three_modules_is_detected_fixed_and_verified(tmp_path):
    rep = run_once(str(APPS / "shop_multifile"), str(tmp_path / "m.db"), seed=0)
    (r,) = rep.results
    assert r.issue_class == "BOLA" and r.func == "show_order"
    assert [lv.fqname for lv in r.finding.path] == [
        "shop.views.show_order", "shop.services.orders.order_details", "shop.repo.load_order"]
    assert r.status == "success" and [ok for _, ok in r.stages] == [True] * 4
    assert "+++ b/shop/views.py" in r.rendered_diff
    assert "+from shop.auth import current_user_id" in r.rendered_diff


# --- §III.E detection -------------------------------------------------------------

_PRE = """
ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}
SENT = []
_S = {"uid": None}
def current_user_id():
    return _S["uid"]
def get_order_by_id(i):
    return ORDERS.get(i)
"""


def _one(tmp_path, body):
    p = tmp_path / "app.py"
    p.write_text(textwrap.dedent(_PRE + body))
    return _classes(p)


def test_guard_after_the_data_escapes_does_not_count(tmp_path):
    assert _one(tmp_path, """
def get_order(order_id):
    order = get_order_by_id(order_id)
    SENT.append(order)
    if order["user_id"] != current_user_id():
        raise PermissionError("x")
    return order
""") == [("BOLA", "get_order")]


def test_guard_helper_in_another_module_clears_by_shape(tmp_path):
    root = _pkg(tmp_path, {
        "app/checks.py": """
            from .session import current_user_id
            def zz(obj):
                if obj["user_id"] != current_user_id():
                    raise PermissionError("no")
        """,
        "app/session.py": "def current_user_id():\n    return 1\n",
        "app/views.py": """
            from .checks import zz
            ORDERS = {}
            def show(oid):
                o = ORDERS.get(oid)
                zz(o)
                return o
        """,
    })
    assert _classes(root) == []


def test_owner_scoped_query_is_not_bola(tmp_path):
    assert _one(tmp_path, """
class Order:
    query = None
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user_id())
    return order
""") == [("BOLA", "get_order_by_id")]      # only the unscoped, uncalled helper


def test_callers_search_requires_every_caller_to_be_guarded(tmp_path):
    base = """
        ACCOUNTS = {1: {}, 2: {}}
        def current_user():
            return {"role": "user"}
        def wipe(account_id):
            ACCOUNTS.pop(account_id, None)
        def admin_panel(account_id):
            if current_user().get("role") != "admin":
                raise PermissionError("forbidden")
            wipe(account_id)
    """
    spec = detect.DetectorSpec("BFLA_UP", sink=detect.SinkMatcher("privileged_mutation"),
                               missing_guard="role", search=detect.CALLERS,
                               fix_template="insert_role_guard_at_start")
    ok = _pkg(tmp_path / "a", {"app.py": base})
    g = graph.build(str(ok / "app.py"))
    # wipe is reached only through the guarded admin panel
    assert [f.func for f in detect.detect_with_spec(spec, g)] == []
    bad = _pkg(tmp_path / "b", {"app.py": base + "\n        def nightly_cleanup(account_id):\n"
                                               "            wipe(account_id)\n"})
    g2 = graph.build(str(bad / "app.py"))
    assert [f.func for f in detect.detect_with_spec(spec, g2)] == ["nightly_cleanup"]


def test_ssrf_anchors_on_library_symbols_not_helper_names(tmp_path):
    root = _pkg(tmp_path, {"app.py": """
        import requests as http
        from urllib.request import urlopen
        def fetch_url(url):
            return {"host": url}
        def preview(url):
            return fetch_url(url)
        def proxy(target):
            r = http.get(target, timeout=2)
            return r.text
        def legacy(u):
            return urlopen(u).read()
    """})
    got = sorted(f.func for f in detect.detect_ssrf(graph.build(str(root / "app.py"))))
    assert got == ["legacy", "proxy"]


@pytest.mark.parametrize("variant", ["flat", "nested", "renamed", "extra_helper"])
def test_structure_invariance_flat_nested_renamed_extra_helper(variant):
    ref = graph.build(str(APPS / "bola_variants" / "flat" / "app.py"))
    ref_fp = fingerprint.compute(detect.detect_all(ref)[0], ref, "none").hex()
    g = graph.build(str(APPS / "bola_variants" / variant / "app.py"))
    (f,) = detect.detect_all(g)
    assert f.issue_class == "BOLA"
    assert fingerprint.compute(f, g, "none").hex() == ref_fp


def test_facets_are_read_off_the_path(tmp_path):
    root = _pkg(tmp_path, {"app.py": """
        from flask import Flask, request
        app = Flask(__name__)
        ORDERS = {}
        @app.route("/orders/<order_id>")
        def show(order_id):
            order = ORDERS.get(order_id)
            return order
        @app.post("/users")
        def create():
            data = request.get_json()
            return make_user(**data)
    """})
    g = graph.build(str(root / "app.py"))
    by = {f.issue_class: f for f in detect.detect_all(g)}
    assert by["BOLA"].source_role == "path_param" and by["BOLA"].sink_category == "object_read"
    assert by["MASS_ASSIGNMENT"].source_role == "body_field"
    assert by["BOLA"].fix_locus == "handler" and g.framework() == "flask"


# --- §III.F templates render from the target AST -----------------------------------

def test_template_renders_in_the_target_codebases_idiom(tmp_path):
    root = _pkg(tmp_path, {"app.py": """
        from flask import Flask
        from flask_login import current_user
        app = Flask(__name__)

        class Invoice:
            owner_id = None
            query = None

        @app.route("/invoices/<int:invoice_id>")
        def invoice(invoice_id):
            inv = Invoice.query.get(invoice_id)
            return inv
    """})
    from codefix.templates import render_patch
    g = graph.build(str(root / "app.py"))
    (f,) = detect.detect_bola(g)
    patch = render_patch("insert_ownership_guard", f, g)
    assert "+    if inv is not None and inv.owner_id != current_user.id:" in patch.diff
    assert "+        abort(403)" in patch.diff
    assert "+from flask import abort" in patch.diff


def test_principal_import_in_a_src_layout_drops_the_source_root(tmp_path):
    root = _pkg(tmp_path, {
        "src/shop/__init__.py": "",
        "src/shop/auth.py": """
        def current_user_id():
            return 1
        """,
        "src/shop/views.py": """
        ORDERS = {}

        def show_order(order_id):
            order = ORDERS.get(order_id)
            return order
        """})
    from codefix.templates import render_patch
    g = graph.build(str(root))
    (f,) = detect.detect_bola(g)
    patch = render_patch(f.transform_id, f, g)
    assert "+from shop.auth import current_user_id" in patch.diff
    assert "src.shop" not in patch.diff


# --- §III.G validator -----------------------------------------------------------------

def _shop_candidate(transform_text):
    from codefix import propose
    from codefix.templates import RenderedPatch
    root = APPS / "shop_bola"
    g = graph.build(str(root), exclude=graph.harness_excluder)
    f = detect.detect_bola(g)[0]
    before = (root / "app.py").read_text()
    after = before.replace("    order = get_order_by_id(order_id)\n    return order",
                           transform_text)
    assert after != before
    patch = RenderedPatch("custom", str(root), {"app.py": (before, after)}, "", "", {})
    return f, propose.Candidate(None, "custom", "custom", 1, 1, 0, 0, "template", "", patch=patch)


def test_contract_stage_rejects_a_fix_that_strips_a_response_field(tmp_path):
    """contract demo: blocks the attack, keeps the owner path, but drops `total`."""
    from codefix.validate import verify
    f, cand = _shop_candidate(
        "    order = get_order_by_id(order_id)\n"
        "    if order is not None and order[\"user_id\"] != current_user_id():\n"
        "        raise PermissionError(\"not owner\")\n"
        "    return {k: v for k, v in order.items() if k != \"total\"}")
    root = APPS / "shop_bola"
    v = verify(f, cand, str(root), str(root / "exploit.py"), str(root / "legit.py"))
    assert v.status == "regression"
    assert ("contract-conformance", False) in v.stages
    assert "total: field removed" in v.detail


def test_a_missing_stage_is_unverified_not_success(tmp_path):
    import shutil
    from codefix.validate import verify
    app = tmp_path / "shop"
    shutil.copytree(APPS / "shop_bola", app)
    (app / "bypass.py").unlink()
    rep = run_once(str(app), str(tmp_path / "u.db"), seed=0)
    (r,) = rep.results
    assert r.status == "unverified" and "adversarial" in r.detail
    c = sqlite3.connect(tmp_path / "u.db")
    assert c.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0] == 0   # nothing learned


# --- §III.C PatchMemory ---------------------------------------------------------------

def test_patch_memory_has_eight_linked_tables_and_outcome_statuses(tmp_path):
    from codefix.memory import PatchMemory, pac_min_observations
    db = str(tmp_path / "pm.db")
    rep = run_once(str(APPS / "shop_bola"), db, seed=0)
    assert rep.results[0].status == "success"
    c = sqlite3.connect(db)
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"codebases", "fingerprints", "issues", "templates", "template_fingerprint_links",
            "patches", "outcomes", "detector_specs"} <= tables
    fks = {t: {r[2] for r in c.execute(f"PRAGMA foreign_key_list({t})")}
           for t in ("issues", "patches", "outcomes", "template_fingerprint_links")}
    assert fks["issues"] == {"codebases", "fingerprints"}
    assert fks["patches"] == {"issues", "templates"}
    assert fks["outcomes"] == {"patches"}
    assert fks["template_fingerprint_links"] == {"templates", "fingerprints"}

    m = PatchMemory(db)
    pid = m.conn.execute("SELECT id FROM patches").fetchone()[0]
    tid, fid = m.conn.execute("SELECT template_id, fingerprint_id FROM template_fingerprint_links"
                              " WHERE successes > 0").fetchone()
    m.mark_superseded(pid)                                   # neutral
    assert m.templates_for(fid, "BOLA")[0].regressions == 0
    m.mark_reverted(pid)                                     # counts against beta
    stat = m.templates_for(fid, "BOLA")[0]
    assert (stat.successes, stat.regressions) == (1, 1)
    assert not m.is_proven(tid, fid)                         # 1/2 over a tiny sample
    assert pac_min_observations() > 2


# --- one defect, many shapes (site: "recognizes the same flaw even when the code
# looks different — different names, split across more functions, flatter or deeper") ---

_SHAPE_PRE = """
ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}
_S = {"uid": None}
def current_user_id():
    return _S["uid"]
"""

SHAPES = {
    "flat": """
def get_order(order_id):
    order = ORDERS.get(order_id)
    return order
""",
    "renamed_helper": """
def zz9(k):
    return ORDERS.get(k)
def h(q):
    x = zz9(q)
    return x
""",
    "class_method_sink": """
class Repo:
    def load(self, i):
        return ORDERS.get(i)
def handler(order_id):
    o = Repo().load(order_id)
    return o
""",
    "subscript_sink": """
def handler(order_id):
    o = ORDERS[order_id]
    return o
""",
    "sink_in_loop_escaping_via_list": """
def handler(ids):
    out = []
    for i in ids:
        o = ORDERS.get(i)
        out.append(o)
    return out
""",
    "sink_in_try": """
def handler(order_id):
    try:
        o = ORDERS.get(order_id)
    except KeyError:
        return None
    return o
""",
    "taint_through_dict_and_fstring": """
def handler(order_id):
    ctx = {"key": order_id}
    k = f"{ctx['key']}"
    o = ORDERS.get(k)
    return o
""",
    "async_handler": """
async def handler(order_id):
    o = ORDERS.get(order_id)
    return o
""",
}


def _shape_graph(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "app.py").write_text(textwrap.dedent(_SHAPE_PRE + body))
    return graph.build(str(d / "app.py"))


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_one_defect_many_shapes_one_fingerprint(tmp_path, name):
    flat = _shape_graph(tmp_path, "flat_ref", SHAPES["flat"])
    ref = fingerprint.compute(detect.detect_all(flat)[0], flat, "none").hex()
    g = _shape_graph(tmp_path, name, SHAPES[name])
    (f,) = detect.detect_all(g)
    assert f.issue_class == "BOLA"
    assert fingerprint.compute(f, g, "none").hex() == ref


def test_a_guard_deep_in_a_helper_still_clears_every_shape(tmp_path):
    g = _shape_graph(tmp_path, "guarded", """
def check(o):
    if o is not None and o["user_id"] != current_user_id():
        raise PermissionError("no")
def get_order(order_id):
    order = ORDERS.get(order_id)
    check(order)
    return order
""")
    assert detect.detect_all(g) == []


def test_chains_deeper_than_the_default_need_the_spec_depth(tmp_path):
    """Alg. 2's search depth defaults to 2; a deeper codebase raises it in the
    spec (data, not engine code) and lands on the same fingerprint."""
    g = _shape_graph(tmp_path, "deep", """
def l4(a):
    return ORDERS.get(a)
def l3(a):
    return l4(a)
def l2(a):
    return l3(a)
def handler(order_id):
    o = l2(order_id)
    return o
""")
    assert detect.detect_all(g) == []                      # 4 hops, default depth 2
    deep = detect.DetectorSpec("BOLA", sink=detect.SinkMatcher("object_read"),
                               missing_guard="ownership", search=detect.BOTH,
                               fix_template="insert_ownership_guard", depth=4)
    (f,) = detect.detect_with_spec(deep, g)
    flat = _shape_graph(tmp_path, "flat_ref2", SHAPES["flat"])
    ref = fingerprint.compute(detect.detect_all(flat)[0], flat, "none").hex()
    assert f.func == "handler" and fingerprint.compute(f, g, "none").hex() == ref
