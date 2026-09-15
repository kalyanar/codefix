"""The engine over a SCIP-derived CallGraphProvider (TypeScript, scip-typescript)."""
from pathlib import Path

from codefix import detect, fingerprint, graph
from codefix.scip import parse_symbol, read_index
from codefix.scipgraph import build_from_scip

TS = Path(__file__).resolve().parents[1] / "bench" / "apps" / "ts_shop_bola"
APPS = TS.parent

# the shipped anchors are Python-flavoured; a TypeScript codebase names its
# principal accessor in the spec — data, not engine code
TS_BOLA = detect.DetectorSpec("BOLA", sink=detect.SinkMatcher("object_read"),
                              missing_guard="ownership", search=detect.BOTH,
                              fix_template="insert_ownership_guard",
                              call_anchors=frozenset({"currentUserId"}))


def test_scip_index_decodes_without_protobuf():
    docs = {d.relative_path: d for d in read_index(TS / "vuln" / "index.scip")}
    assert set(docs) == {"src/auth.ts", "src/repo.ts", "src/service.ts", "src/routes.ts"}
    defs = [o for o in docs["src/repo.ts"].occurrences if o.roles & 1 and o.enclosing_range]
    assert any(parse_symbol(o.symbol).fqname == "src.repo.loadOrder" for o in defs)


def test_symbol_parser():
    p = parse_symbol("scip-typescript npm ts-shop-bola-vuln 1.0.0 src/`repo.ts`/loadOrder().")
    assert (p.fqname, p.name, p.module, p.kind) == ("src.repo.loadOrder", "loadOrder", "src.repo",
                                                    "function")
    m = parse_symbol("scip-python python app 1.0 app/views/`OrderView`#get().")
    assert m.kind == "method" and m.parent_class == "OrderView" and m.name == "get"


def test_scip_provider_resolves_cross_file_edges():
    g = build_from_scip(str(TS / "vuln" / "index.scip"))
    assert g.language == "typescript"
    edges = {(e.caller, e.callee_fqname) for e in g.edges}
    assert ("src.routes.showOrder", "src.service.orderDetails") in edges
    assert ("src.service.orderDetails", "src.repo.loadOrder") in edges
    assert any(e.callee_name == "ORDERS.get" and e.callee_fqname is None for e in g.edges)


def test_same_engine_detects_the_typescript_bola_across_three_modules():
    g = build_from_scip(str(TS / "vuln" / "index.scip"))
    (f,) = detect.detect_with_spec(TS_BOLA, g)
    assert f.fqname == "src.routes.showOrder"
    assert [lv.fqname for lv in f.path] == ["src.routes.showOrder", "src.service.orderDetails",
                                            "src.repo.loadOrder"]


def test_dominance_holds_on_the_scip_provider():
    assert detect.detect_with_spec(TS_BOLA, build_from_scip(str(TS / "safe" / "index.scip"))) == []
    skip = detect.detect_with_spec(TS_BOLA, build_from_scip(str(TS / "skippable" / "index.scip")))
    assert [f.fqname for f in skip] == ["src.routes.showOrder"]     # guard in a skippable branch


def test_typescript_and_python_bola_share_one_fingerprint():
    ts = build_from_scip(str(TS / "vuln" / "index.scip"))
    (f_ts,) = detect.detect_with_spec(TS_BOLA, ts)
    py = graph.build(str(APPS / "shop_multifile"), exclude=graph.harness_excluder)
    (f_py,) = detect.detect_bola(py)
    assert fingerprint.compute(f_ts, ts, "none").hex() == fingerprint.compute(f_py, py, "none").hex()
