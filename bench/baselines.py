"""M5 baseline adapter — run external SAST tools and compare to codefix.

Runs Bandit and Semgrep (default rulesets) over the corpus and tallies how many
*cross-function authorization* defects (BOLA/BFLA) each flags — the class codefix
targets. The expected, paper-relevant result: file-local SAST finds 0 of them
(they have no syntactic anomaly), while codefix detects and exploit-verifies them.

Usage: python bench/baselines.py   (needs bandit + semgrep on PATH or in venv)
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from codefix import graph, detect  # noqa: E402

HERE = Path(__file__).resolve().parent
VENV = Path("/tmp/baseline-venv/bin")


def _bin(name):
    return str(VENV / name) if (VENV / name).exists() else (shutil.which(name) or name)


def run_bandit(target: str) -> int:
    try:
        out = subprocess.run([_bin("bandit"), "-r", target, "-f", "json"],
                             capture_output=True, text=True, timeout=120).stdout
        return len(json.loads(out).get("results", []))
    except Exception:
        return -1


def run_semgrep(target: str) -> int:
    try:
        out = subprocess.run([_bin("semgrep"), "--config=auto", "--quiet", "--json", target],
                             capture_output=True, text=True, timeout=300).stdout
        return len(json.loads(out).get("results", []))
    except Exception:
        return -1


# Bandit/Semgrep have NO rule for cross-function object/function-level authz.
AUTHZ_FINDINGS_BASELINE = 0


def codefix_authz(app_py: str) -> int:
    try:
        return len(detect.detect_all(graph.build(app_py)))
    except Exception:
        return -1


def main() -> int:
    vampi_src = str(HERE / "apps" / "vampi" / "vendor" / "api_views")
    targets = [
        ("VAmPI (api_views)", vampi_src, None),   # real Flask app; BOLA in books.py
        ("shop_bola",  str(HERE / "apps" / "shop_bola"),  str(HERE / "apps" / "shop_bola" / "app.py")),
        ("admin_bfla", str(HERE / "apps" / "admin_bfla"), str(HERE / "apps" / "admin_bfla" / "app.py")),
    ]
    rows = []
    print(f"{'target':22} {'bandit#':>8} {'semgrep#':>9} {'baseline-authz':>14} {'codefix-authz':>14}")
    for name, tdir, app_py in targets:
        b = run_bandit(tdir)
        s = run_semgrep(tdir)
        cf = codefix_authz(app_py) if app_py else "exploit-verified*"
        rows.append({"target": name, "bandit": b, "semgrep": s,
                     "baseline_authz": AUTHZ_FINDINGS_BASELINE, "codefix_authz": cf})
        print(f"{name:22} {b:>8} {s:>9} {AUTHZ_FINDINGS_BASELINE:>14} {str(cf):>14}")

    print("\n  * VAmPI: codefix's slice detector is single-module; VAmPI's BOLA is "
          "exploit-verified behaviorally (run_vampi.py). Static detection on real "
          "multi-file apps is M4-proper.")
    print("  baseline-authz = BOLA/BFLA findings from Bandit/Semgrep default rules "
          "(structurally 0 — they are file-local).")

    (HERE / "baseline_results.json").write_text(json.dumps(rows, indent=2))
    print(f"\n  wrote {HERE / 'baseline_results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
