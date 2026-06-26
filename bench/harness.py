"""Benchmark harness (M1) — run the corpus and emit F1/F2 metrics.

Runs partition A (train) then B (transfer) on a shared PatchMemory DB, so the
warm-start rate on B is the F2 signal. In-process apps run the full codefix loop;
docker apps run their exploit-verification runner. Writes bench/results.json.

Usage:
  python bench/harness.py            # in-process corpus
  python bench/harness.py --with-docker   # also boot+verify dockerized apps
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from codefix.orchestrate import run_once  # noqa: E402

HERE = Path(__file__).resolve().parent


def run_inprocess(app, db):
    rep = run_once(str(HERE / app["path"]), db, seed=0)
    rows = []
    for r in rep.results:
        rows.append({
            "app": app["name"], "partition": app["partition"],
            "issue_class": r.issue_class, "func": r.func, "fp": r.fp_hex,
            "provenance": r.provenance, "llm_used": r.llm_used,
            "warm": r.warm, "status": r.status,
        })
    return rows


def run_docker(app):
    runner = HERE / app["path"] / app.get("runner", "run.py")
    if not runner.exists():
        return [{"app": app["name"], "partition": app["partition"],
                 "status": "skipped", "detail": "no runner"}]
    proc = subprocess.run([sys.executable, str(runner)], capture_output=True, text=True)
    status = "success" if proc.returncode == 0 else "failed"
    return [{"app": app["name"], "partition": app["partition"],
             "issue_class": ",".join(app.get("classes", [])),
             "status": status, "kind": "docker"}]


def main(argv=None) -> int:
    with_docker = "--with-docker" in (argv or sys.argv[1:])
    manifest = json.loads((HERE / "manifest.json").read_text())
    db = str(HERE / ".bench.db")
    Path(db).unlink(missing_ok=True)

    # partition A (train) before B (transfer)
    apps = sorted(manifest["apps"], key=lambda a: a["partition"])
    rows = []
    for app in apps:
        if app["kind"] == "inprocess":
            rows += run_inprocess(app, db)
        elif app["kind"] == "docker" and with_docker:
            rows += run_docker(app)

    # metrics
    verified = [r for r in rows if r.get("status") in ("success", "regression")]
    inproc = [r for r in rows if "llm_used" in r]
    f1_success = sum(1 for r in inproc if r["status"] == "success") / max(len(inproc), 1)
    f1_llm_rate = sum(1 for r in inproc if r["llm_used"]) / max(len(inproc), 1)
    b = [r for r in inproc if r["partition"] == "B"]
    f2_warm_rate = sum(1 for r in b if r["warm"]) / max(len(b), 1)

    print(f"{'app':18} {'part':4} {'class':6} {'prov':10} {'warm':5} status")
    for r in rows:
        print(f"{r['app']:18} {r['partition']:4} {r.get('issue_class',''):6} "
              f"{r.get('provenance',''):10} {str(r.get('warm','')):5} {r.get('status','')}")
    print("\n== benchmark metrics ==")
    print(f"  apps run:                 {len({r['app'] for r in rows})}")
    print(f"  F1 exploit-verified rate: {f1_success:.2f}")
    print(f"  F1 LLM-call rate:         {f1_llm_rate:.2f}")
    print(f"  F2 warm-start rate on B:  {f2_warm_rate:.2f}  (transfer)")

    out = {"rows": rows, "metrics": {
        "f1_success": f1_success, "f1_llm_rate": f1_llm_rate,
        "f2_warm_rate_B": f2_warm_rate}}
    (HERE / "results.json").write_text(json.dumps(out, indent=2))
    print(f"\n  wrote {HERE / 'results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
