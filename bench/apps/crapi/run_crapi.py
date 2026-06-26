"""crAPI exploit-verification runner (M1 corpus expansion).

crAPI is OWASP's deliberately-vulnerable API app — rich in BOLA/BFLA/mass-assign,
the closest public app to codefix's target class. Unlike VAmPI it is a
multi-container stack (identity[Java] + community[Go] + workshop[Python] +
postgres + mongo + chromadb + mailhog + gateway + web).

Auth flow (needed before any exploit):
  1. POST /identity/api/auth/signup   {name,email,number,password}
  2. POST /identity/api/auth/login    {email,password} -> JWT (Bearer)
     (some flows email an OTP/token retrievable from mailhog at :8025
      GET /api/v2/messages -> parse the body)

Target BOLA (canonical crAPI):
  GET /identity/api/v2/vehicle/{vehicleId}/location  -> another user's vehicle
  (or the mechanic/service-report BOLA in workshop). vehicleId is mailed on
  signup; retrieve via mailhog.

This runner: compose up -> wait healthy -> (exploit TBD after bring-up) -> down.
Filled in once the stack is reachable and the exact endpoints are confirmed.
"""
import subprocess
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yml"
API = "http://localhost:8888"
MAILHOG = "http://localhost:8025"


def compose(*args, timeout=1200):
    return subprocess.run(["docker", "compose", "-f", str(COMPOSE), *args],
                          capture_output=True, text=True, timeout=timeout)


def wait_healthy(tries=90) -> bool:
    for _ in range(tries):
        try:
            # crAPI web serves the SPA at :8888; the identity API is proxied under /identity
            if requests.get(f"{API}/identity/api/auth/signup", timeout=4).status_code in (200, 400, 405):
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def mailhog_latest_for(email: str) -> str:
    """Best-effort: pull the latest mailhog message body for an address (OTP/token)."""
    try:
        msgs = requests.get(f"{MAILHOG}/api/v2/messages", timeout=5).json().get("items", [])
        for m in msgs:
            to = ",".join(a.get("Mailbox", "") + "@" + a.get("Domain", "") for a in m.get("To", []))
            if email in to:
                return m.get("Content", {}).get("Body", "")
    except Exception:
        pass
    return ""


def main() -> int:
    print("== bringing up crAPI (multi-container) ==")
    up = compose("up", "-d")
    if up.returncode != 0:
        print(up.stderr[-2000:]); return 2
    try:
        if not wait_healthy():
            print("crAPI did not become healthy at", API); return 3
        print("crAPI reachable at", API)

        def run(script):
            p = subprocess.run([sys.executable, str(HERE / script), "--base-url", API],
                               capture_output=True, text=True, timeout=90)
            print(f"    $ {script}\n      {p.stdout.strip()}")
            return p.returncode

        print("\n== exploit-verification (shop-order BOLA) ==")
        exploit_present = run("exploit.py") == 0     # BOLA present on real app
        legit_ok = run("legit.py") == 0              # owner path works
        print(f"\n  [BOLA] shop-order  exploit-confirmed={exploit_present}  legit={legit_ok}")
        print("  NOTE: crAPI ships no 'secure' variant — this establishes ground "
              "truth (BOLA present, card data leaked). The patched-after half is "
              "codefix patching crAPI's Python workshop service (M4/M8).")
        return 0 if (exploit_present and legit_ok) else 1
    finally:
        print("== tearing down ==")
        compose("down", timeout=300)


if __name__ == "__main__":
    sys.exit(main())
