"""codefix on the live OWASP apps: detect -> render its own fix -> exploit-verify live.

For VAmPI (Flask) and crAPI's workshop service (Django), codefix scans the real
multi-file source tree, renders its fix for each labelled defect from that
codebase's own AST (rescanning after each fix so later fixes see patched code),
writes the patched tree, and hands it to the app's live harness
(`run_vampi.py` / `run_crapi.py --patched-src`), which serves the unmodified
source as "before" and codefix's tree as "after" and runs the four validator
stages over HTTP. The verdict is recorded in PatchMemory; each verified fix gets
a PR draft.

Usage:
  python bench/live_codefix.py vampi [--db PATH] [--pr DIR] [--render-only]
  python bench/live_codefix.py crapi [--db PATH] [--pr DIR] [--render-only]
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
from codefix import detect, fingerprint, graph  # noqa: E402
from codefix.memory import PatchMemory  # noqa: E402
from codefix.pr import make_pr_draft  # noqa: E402
from codefix.templates import render_patch  # noqa: E402

APPS = {
    "vampi": {"dir": HERE / "apps" / "vampi", "source": "vendor", "runner": "run_vampi.py",
              "names": {"books-read": "get_by_title", "pw-takeover": "update_password"}},
    "crapi": {"dir": HERE / "apps" / "crapi", "source": "vendor", "runner": "run_crapi.py",
              "names": {"shop-order": "OrderControlView.get"}},
}


@dataclass
class LiveResult:
    func: str
    issue_class: str
    fp_hex: str
    fp_label: str
    missing_guard_class: str
    provenance: str = "template"
    status: str = "unverified"
    posterior: float = 0.5
    rendered_diff: str = ""
    guard: str = ""
    stages: list = field(default_factory=list)


def _matches(f, want):
    return f.fqname.endswith("." + want) or f.func == want


def render_tree(app: str, out: Path):
    cfg = APPS[app]
    src = cfg["dir"] / cfg["source"]
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(src, out, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    wanted = dict(cfg["names"])
    rendered = {}
    first_graph = graph.build(str(out), exclude=graph.harness_excluder)
    framework = first_graph.framework()
    all_findings = detect.detect_all(first_graph)
    for _ in range(len(wanted) + 2):
        g = graph.build(str(out), exclude=graph.harness_excluder)
        todo = [(name, f) for f in detect.detect_all(g)
                for name, fn in wanted.items() if _matches(f, fn)]
        if not todo:
            break
        name, f = todo[0]
        patch = render_patch(f.transform_id, f, g)
        key = fingerprint.compute(f, g, framework)
        rendered[name] = (f, patch, key)
        patch.write_to(str(out))
        wanted.pop(name)
    return rendered, wanted, all_findings, first_graph


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("app", choices=sorted(APPS))
    ap.add_argument("--db", default=None)
    ap.add_argument("--pr", default=None)
    ap.add_argument("--out", default=None, help="where to write codefix's patched tree")
    ap.add_argument("--render-only", action="store_true")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--verdict", default=None, help="use an existing runner verdict for this tree")
    args = ap.parse_args(argv)
    cfg = APPS[args.app]
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix=f"codefix_{args.app}_")) / "src"

    rendered, missed, findings, g0 = render_tree(args.app, out)
    print(f"== codefix scan of {args.app} source: {len(g0.sources)} files, "
          f"{len(g0.functions)} functions, {g0.build_seconds * 1000:.0f} ms ==")
    for f in findings:
        print(f"  [{f.issue_class}] {f.fqname} ({Path(f.sink_file).name}:{f.sink_lineno})")
    for name, (f, patch, key) in rendered.items():
        print(f"\n== {name}: {f.issue_class} in {f.fqname}  fp={key.hex()} ==")
        print(patch.diff)
    if missed:
        print(f"NOT DETECTED/RENDERED: {sorted(missed)}")
    if args.render_only:
        print(f"patched tree: {out}")
        return 0 if not missed else 1

    verdict_path = out.parent / "verdict.json"
    if args.verdict:
        # re-record an earlier live run of this exact patched tree
        verdict_path = Path(args.verdict)
    else:
        proc = subprocess.run([sys.executable, str(cfg["dir"] / cfg["runner"]),
                               "--patched-src", str(out), "--json", str(verdict_path)],
                              text=True, capture_output=True, timeout=3600)
        print(proc.stdout[-4000:])
    verdict = json.loads(verdict_path.read_text()) if verdict_path.exists() else {"defects": []}
    if "defects" not in verdict and "stages" in verdict:          # single-defect runner (crAPI)
        verdict = {"defects": [dict(verdict, name=next(iter(cfg["names"])))]}
    by_name = {d["name"]: d for d in verdict.get("defects", [])}

    results = []
    mem = PatchMemory(args.db) if args.db else None
    codebase = mem.upsert_codebase(str(cfg["dir"] / cfg["source"]), "python", g0.framework()) if mem else None
    for name, (f, patch, key) in rendered.items():
        d = by_name.get(name, {})
        st = d.get("stages", {})
        stages = [("exploit-blocked", bool(st.get("exploit_before") and st.get("blocked_after"))),
                  ("differential-legit", bool(st.get("differential_legit"))),
                  ("contract-conformance", bool(st.get("contract"))),
                  ("adversarial-bypass", bool(st.get("adversarial")))]
        ok = bool(d.get("pass")) and all(v for _, v in stages)
        r = LiveResult(f.func, f.issue_class, key.hex(), fingerprint.label(key, f),
                       f.missing_guard_class, status="success" if ok else "regression",
                       rendered_diff=patch.diff, guard=patch.guard, stages=stages)
        results.append(r)
        if mem:
            fp = mem.upsert_fingerprint(key)
            tid = mem.seed_template({"insert_ownership_guard": "bola_ownership_guard"}.get(
                f.transform_id, f.transform_id), f.issue_class, f.transform_id)
            mem.link(tid, fp)
            issue = mem.record_issue(codebase, fp, f.issue_class, f"{f.sink_file}:{f.sink_lineno}:{f.func}")
            pid = mem.record_patch(issue, tid, "template", patch.diff)
            mem.record_outcome(pid, r.status, "exploit", f"live {args.app} {name}")
        if args.pr and ok:
            Path(args.pr).mkdir(parents=True, exist_ok=True)
            make_pr_draft(args.app, r, exploit_name=f"live {name} reproducer").write(
                str(Path(args.pr) / f"{args.app}_{name}.md"))
        print(f"  [{r.issue_class}] {name}: {r.status}  " +
              " ".join(f"{n}={'ok' if v else 'FAIL'}" for n, v in stages))
    if mem:
        mem.close()
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"app": args.app, "patched_tree": str(out), "missed": sorted(missed),
             "results": [{"name": n, "status": r.status, "stages": dict(r.stages),
                          "fingerprint": r.fp_hex, "diff": r.rendered_diff}
                         for n, r in zip(rendered, results)]}, indent=2))
    ok = not missed and results and all(r.status == "success" for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
