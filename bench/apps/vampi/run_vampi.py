"""Live before / after-patch differential harness for VAmPI (dockerized, HTTP).

Two builds of the SAME VAmPI source run side by side, BOTH with vulnerable=1, so
the only difference is the code patch (not VAmPI's own `vulnerable` secure flag):

  :5002  the UNMODIFIED vulnerable source (from vendor/)           -> "before"
  :5001  a build of --patched-src (default: an unmodified vendor/) -> "after"

For each of the two exploit-verified BOLAs (books-read secret leak, and
password-takeover) it runs the four validator stages:

  exploit      attacker path SUCCEEDS on :5002 (before) and is BLOCKED on :5001 (after)
  differential the legit owner path still works on :5001 (no regression)
  contract     the owner's legit response still has the right keys + value types
  adversarial  a varied second attacker (different user/object/shape) is also blocked

The DEFAULT run (no --patched-src) builds :5001 from the unmodified source, so it
is still vulnerable: "after" does NOT block. That is the honest baseline before a
real fix is plugged in. Point --patched-src at codefix's patched source tree (or
a hand patch) to make the after-fix stages pass.

Exit 0  => every stage of every defect held.  Exit 1 => at least one stage failed.
Machine-readable verdict written with --json OUT.

Usage:
  python run_vampi.py                         # baseline (both vulnerable)
  python run_vampi.py --patched-src DIR       # after = built from patched tree
  python run_vampi.py --patched-src DIR --json verdict.json
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor"

# (name, class, exploit, legit, adversarial)
DEFECTS = [
    ("books-read",  "BOLA", "exploit.py",    "legit.py",    "adversarial.py"),
    ("pw-takeover", "BOLA", "exploit_pw.py", "legit_pw.py", "adversarial_pw.py"),
]


def sh(*args, timeout=1200):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def build_ctx(src: Path, dst: Path):
    """Copy a VAmPI source tree into a clean build context; ensure a Dockerfile."""
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", "database.db"))
    if not (dst / "Dockerfile").exists():
        # patched-src supplied only source files: borrow vendor's build files
        for f in ("Dockerfile", "requirements.txt", ".dockerignore"):
            if (VENDOR / f).exists():
                shutil.copy2(VENDOR / f, dst / f)


def docker_build(ctx: Path, tag: str):
    r = sh("docker", "build", "-t", tag, str(ctx))
    if r.returncode != 0:
        print(r.stdout[-1500:]); print(r.stderr[-2000:])
        raise RuntimeError(f"docker build failed for {tag}")


def docker_run(tag: str, name: str, port: int):
    sh("docker", "rm", "-f", name, timeout=60)
    r = sh("docker", "run", "-d", "--name", name,
           "-e", "vulnerable=1", "-e", "tokentimetolive=3600",
           "-p", f"{port}:5000", tag, timeout=120)
    if r.returncode != 0:
        print(r.stderr[-2000:])
        raise RuntimeError(f"docker run failed for {name}")


def wait_healthy(base: str, tries=60) -> bool:
    for _ in range(tries):
        try:
            if requests.get(f"{base}/", timeout=3).status_code == 200:
                requests.get(f"{base}/createdb", timeout=10)  # create + seed tables
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def run_repro(script: str, base: str) -> dict:
    """Run a reproducer; return its RESULT json (plus exit code)."""
    p = subprocess.run([sys.executable, str(HERE / script), "--base-url", base],
                       capture_output=True, text=True, timeout=90)
    result = {"exit": p.returncode, "raw": p.stdout.strip()}
    for line in p.stdout.splitlines():
        if line.startswith("RESULT "):
            try:
                result.update(json.loads(line[len("RESULT "):]))
            except Exception:
                pass
    return result


def check_contract(defect: str, legit: dict):
    """Owner legit response must keep the expected keys + value types."""
    body = legit.get("body") or {}
    if defect == "books-read":
        schema = {"book_title": str, "secret": str, "owner": str}
        missing = [k for k in schema if k not in body]
        badtype = [k for k in schema if k in body and not isinstance(body[k], schema[k])]
        ok = not missing and not badtype
        detail = {"expected": {k: v.__name__ for k, v in schema.items()},
                  "missing": missing, "wrong_type": badtype, "got_keys": sorted(body)}
        return ok, detail
    if defect == "pw-takeover":
        # 204 success; if a body is present it must carry status + Password strings
        status_ok = legit.get("status") == 204
        body_ok = True
        detail = {"expected_status": 204, "got_status": legit.get("status")}
        if body:
            schema = {"status": str, "Password": str}
            missing = [k for k in schema if k not in body]
            badtype = [k for k in schema if k in body and not isinstance(body[k], schema[k])]
            body_ok = not missing and not badtype
            detail.update({"expected_keys": list(schema), "missing": missing,
                           "wrong_type": badtype, "got_keys": sorted(body)})
        return (status_ok and body_ok), detail
    return False, {"error": "unknown defect"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--patched-src", default=None,
                    help="VAmPI source tree for the 'after' build (default: unmodified vendor/)")
    ap.add_argument("--json", dest="json_out", default=None, help="write machine-readable verdict")
    ap.add_argument("--vuln-port", type=int, default=5002)
    ap.add_argument("--patched-port", type=int, default=5001)
    ap.add_argument("--keep", action="store_true", help="leave containers running")
    args = ap.parse_args()

    patched_src = Path(args.patched_src).resolve() if args.patched_src else VENDOR
    vuln_base = f"http://localhost:{args.vuln_port}"
    patched_base = f"http://localhost:{args.patched_port}"
    tmp = Path(tempfile.mkdtemp(prefix="vampi-live-"))
    names = ("vampi-live-vuln", "vampi-live-patched")

    print(f"== VAmPI live before/after harness ==")
    print(f"  before (:{args.vuln_port}) = vendor/ (unmodified, vulnerable=1)")
    print(f"  after  (:{args.patched_port}) = {patched_src}  (vulnerable=1)")

    verdict = {"app": "VAmPI", "patched_src": str(patched_src),
               "vuln_base": vuln_base, "patched_base": patched_base, "defects": []}
    rc = 0
    try:
        print("\n== building images ==")
        vctx, pctx = tmp / "vuln", tmp / "patched"
        build_ctx(VENDOR, vctx); docker_build(vctx, "vampi-live-vuln:latest")
        build_ctx(patched_src, pctx); docker_build(pctx, "vampi-live-patched:latest")

        print("== starting containers ==")
        docker_run("vampi-live-vuln:latest", names[0], args.vuln_port)
        docker_run("vampi-live-patched:latest", names[1], args.patched_port)
        for label, base in (("before/vulnerable", vuln_base), ("after/patched", patched_base)):
            if not wait_healthy(base):
                print(f"  {label} at {base} did not become healthy"); return 3
            print(f"  {label} healthy at {base}")

        print("\n== validator stages (per defect) ==")
        all_ok = True
        for name, cls, exploit, legit_s, adv in DEFECTS:
            before = run_repro(exploit, vuln_base)
            after = run_repro(exploit, patched_base)
            legit = run_repro(legit_s, patched_base)
            adv_r = run_repro(adv, patched_base)

            exploit_ok = bool(before.get("leaked"))          # succeeds before
            blocked_ok = not bool(after.get("leaked"))        # blocked after
            legit_ok = bool(legit.get("ok"))                  # differential
            contract_ok, contract_detail = check_contract(name, legit)
            adversarial_ok = not bool(adv_r.get("leaked"))    # varied attacker blocked

            ok = exploit_ok and blocked_ok and legit_ok and contract_ok and adversarial_ok
            all_ok &= ok
            print(f"  [{cls}] {name:12} exploit-before={exploit_ok} blocked-after={blocked_ok} "
                  f"legit={legit_ok} contract={contract_ok} adversarial={adversarial_ok} "
                  f"-> {'PASS' if ok else 'FAIL'}")
            verdict["defects"].append({
                "name": name, "class": cls, "pass": ok,
                "stages": {"exploit_before": exploit_ok, "blocked_after": blocked_ok,
                           "differential_legit": legit_ok, "contract": contract_ok,
                           "adversarial": adversarial_ok},
                "contract_detail": contract_detail,
                "raw": {"before": before, "after": after, "legit": legit, "adversarial": adv_r},
            })

        verdict["pass"] = all_ok
        print(f"\n  => VAmPI verdict: {'PASS' if all_ok else 'FAIL'} "
              f"({len(DEFECTS)} defects, 4 validator stages each)")
        rc = 0 if all_ok else 1
    finally:
        if not args.keep:
            print("\n== tearing down ==")
            for n in names:
                sh("docker", "rm", "-f", n, timeout=60)
        shutil.rmtree(tmp, ignore_errors=True)
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(verdict, indent=2))
            print(f"  wrote {args.json_out}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
