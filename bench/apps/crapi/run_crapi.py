"""Live before / after-patch differential harness for crAPI's shop-order BOLA.

crAPI is OWASP's deliberately-vulnerable multi-service API app (identity[Java] +
community[Go] + workshop[Python/Django] + postgres + mongo + chromadb + mailhog +
chatbot + gateway + web). The shop-order BOLA lives in the Python **workshop**
service, which is the only service codefix patches here.

Strategy (fast: reuse pulled base images, rebuild only the workshop service):

  1. bring the stock stack up (workshop = crapi/crapi-workshop:latest)
  2. BEFORE: confirm the exploit works and the owner legit path works
  3. rebuild ONLY the workshop image from --patched-src, recreate just that one
     container (DB + all other services stay up and seeded)
  4. AFTER: exploit BLOCKED, legit + contract + adversarial all pass

The DEFAULT run (no --patched-src) rebuilds workshop from the unmodified vendored
source, so "after" is still vulnerable -- the honest baseline before a real fix is
plugged in. Point --patched-src at codefix's patched workshop tree to pass.

Exit 0 => every stage held.  Exit 1 => at least one stage failed.
Machine-readable verdict via --json OUT.

Usage:
  python run_crapi.py                        # baseline (workshop still vulnerable after)
  python run_crapi.py --patched-src DIR --json verdict.json
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yml"
VENDOR = HERE / "vendor"
API = "http://127.0.0.1:8888"
PATCHED_TAG = "crapi-workshop-live:patched"
WORKSHOP = "crapi-workshop"


def sh(*args, timeout=1800):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def compose(*args, timeout=1800):
    return sh("docker", "compose", "-f", str(COMPOSE), *args, timeout=timeout)


def compose_override(override: Path, *args, timeout=1800):
    return sh("docker", "compose", "-f", str(COMPOSE), "-f", str(override), *args, timeout=timeout)


def container_health(name: str) -> str:
    r = sh("docker", "inspect", "-f", "{{.State.Health.Status}}", name, timeout=30)
    return r.stdout.strip()


def wait_health(name: str, tries=60) -> bool:
    for _ in range(tries):
        if container_health(name) == "healthy":
            return True
        time.sleep(4)
    return False


def wait_http(url: str, tries=60) -> bool:
    for _ in range(tries):
        try:
            if requests.get(url, timeout=4).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def run_repro(script: str) -> dict:
    p = subprocess.run([sys.executable, str(HERE / script), "--base-url", API],
                       capture_output=True, text=True, timeout=120)
    result = {"exit": p.returncode, "raw": p.stdout.strip()}
    for line in p.stdout.splitlines():
        if line.startswith("RESULT "):
            try:
                result.update(json.loads(line[len("RESULT "):]))
            except Exception:
                pass
    return result


def check_contract(legit: dict):
    """Owner's legit order+payment response must keep expected keys + value types."""
    body = legit.get("body") or {}
    order = body.get("order") or {}
    payment = body.get("payment") or {}
    problems = []

    order_types = {"id": int, "quantity": int, "status": str,
                   "transaction_id": str, "created_on": str}
    for k, t in order_types.items():
        if k not in order:
            problems.append(f"order.{k} missing")
        elif not isinstance(order[k], t):
            problems.append(f"order.{k} wrong type")
    for k in ("email", "number"):
        if k not in (order.get("user") or {}):
            problems.append(f"order.user.{k} missing")
    for k in ("id", "name", "price"):
        if k not in (order.get("product") or {}):
            problems.append(f"order.product.{k} missing")
    # payment card record must survive for the owner's own legitimate view
    for k in ("card_number", "card_owner_name", "card_type", "card_expiry"):
        if k not in payment:
            problems.append(f"payment.{k} missing")

    detail = {"order_keys": sorted(order), "payment_keys": sorted(payment),
              "problems": problems}
    return (not problems), detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--patched-src", default=None,
                    help="workshop source tree for the 'after' build (default: unmodified vendor/)")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--keep", action="store_true", help="leave the stack running")
    args = ap.parse_args()

    patched_src = Path(args.patched_src).resolve() if args.patched_src else VENDOR
    override = HERE / ".workshop_patched.override.yml"
    override.write_text("services:\n  crapi-workshop:\n    image: %s\n" % PATCHED_TAG)

    verdict = {"app": "crAPI", "defect": "shop-order", "class": "BOLA",
               "patched_src": str(patched_src), "api": API}
    rc = 0
    print("== crAPI live before/after harness (workshop shop-order BOLA) ==")
    try:
        print("\n== building patched workshop image from source ==")
        b = sh("docker", "build", "-t", PATCHED_TAG, str(patched_src))
        if b.returncode != 0:
            print(b.stdout[-1200:]); print(b.stderr[-1600:]); return 2

        print("== bringing up stock stack (chatbot first so web's nginx resolves it) ==")
        # chatbot + its deps + workshop(stock) + gateway; then web on top
        up1 = compose("up", "-d", "crapi-chatbot", "crapi-workshop",
                      "api.mypremiumdealership.com")
        if up1.returncode != 0:
            print(up1.stderr[-1600:]); return 2
        if not wait_health(WORKSHOP):
            print("  stock workshop did not become healthy"); return 3
        up2 = compose("up", "-d", "crapi-web")
        if up2.returncode != 0:
            print(up2.stderr[-1600:]); return 2
        if not wait_http(f"{API}/health"):
            print("  crAPI web did not become healthy at", API); return 3
        print("  stock stack reachable at", API)

        print("\n== BEFORE (stock workshop) ==")
        before = run_repro("exploit.py")
        legit_before = run_repro("legit.py")
        exploit_ok = bool(before.get("leaked"))
        print(f"  exploit-confirmed={exploit_ok}  legit={bool(legit_before.get('ok'))}")

        print("\n== swapping in patched workshop (rebuild only this service) ==")
        sw = compose_override(override, "up", "-d", "--no-deps",
                              "--force-recreate", "crapi-workshop")
        if sw.returncode != 0:
            print(sw.stderr[-1600:]); return 2
        if not wait_health(WORKSHOP):
            print("  patched workshop did not become healthy"); return 3

        print("== AFTER (patched workshop) ==")
        after = run_repro("exploit.py")
        legit = run_repro("legit.py")
        adv = run_repro("adversarial.py")
        blocked_ok = not bool(after.get("leaked"))
        legit_ok = bool(legit.get("ok"))
        contract_ok, contract_detail = check_contract(legit)
        adversarial_ok = not bool(adv.get("leaked"))

        ok = exploit_ok and blocked_ok and legit_ok and contract_ok and adversarial_ok
        print(f"\n  [BOLA] shop-order  exploit-before={exploit_ok} blocked-after={blocked_ok} "
              f"legit={legit_ok} contract={contract_ok} adversarial={adversarial_ok} "
              f"-> {'PASS' if ok else 'FAIL'}")
        verdict.update({
            "pass": ok,
            "stages": {"exploit_before": exploit_ok, "blocked_after": blocked_ok,
                       "differential_legit": legit_ok, "contract": contract_ok,
                       "adversarial": adversarial_ok},
            "contract_detail": contract_detail,
            "raw": {"before": before, "legit_before": legit_before,
                    "after": after, "legit": legit, "adversarial": adv},
        })
        print(f"\n  => crAPI verdict: {'PASS' if ok else 'FAIL'} (4 validator stages)")
        rc = 0 if ok else 1
    finally:
        if not args.keep:
            print("\n== tearing down ==")
            compose("down", "-v", timeout=600)
        override.unlink(missing_ok=True)
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(verdict, indent=2))
            print(f"  wrote {args.json_out}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
