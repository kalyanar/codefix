"""Boot dockerized VAmPI (vulnerable :5002 + secure :5001), run the HTTP
exploit + legit reproducers against each, and print the exploit-verification
verdict. This is M1 (benchmark + exploit harness) and the exploit-verify core
of M2, against a REAL running service.

The secure variant (vulnerable=0) stands in for "the patched app" — VAmPI ships
the fixed owner-check in the else-branch of get_by_title. codefix's own
generated fix (transforming the vulnerable source) is the M4/M8 integration.

Usage: python run_vampi.py
"""
import subprocess
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "vendor" / "docker-compose.yaml"
VULN = "http://localhost:5002"
SECURE = "http://localhost:5001"


def compose(*args: str, timeout=900) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def wait_healthy(base: str, tries=60) -> bool:
    """Poll '/' until it serves, then seed the DB via VAmPI's /createdb."""
    for _ in range(tries):
        try:
            if requests.get(f"{base}/", timeout=3).status_code == 200:
                requests.get(f"{base}/createdb", timeout=10)  # create + seed tables
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def run_script(script: str, base: str) -> int:
    p = subprocess.run([sys.executable, str(HERE / script), "--base-url", base],
                       capture_output=True, text=True, timeout=60)
    print(f"    $ {script} --base-url {base}\n      {p.stdout.strip()}")
    return p.returncode


def main() -> int:
    print("== building + starting VAmPI (vulnerable :5002, secure :5001) ==")
    up = compose("up", "-d", "--build")
    if up.returncode != 0:
        print(up.stderr[-2000:])
        return 2
    try:
        for name, base in (("vulnerable", VULN), ("secure", SECURE)):
            if not wait_healthy(base):
                print(f"  {name} at {base} did not become healthy")
                return 3
            print(f"  {name} healthy at {base}")

        # (name, class, exploit script, legit script)
        vulns = [
            ("books-read",  "BOLA", "exploit.py",    "legit.py"),
            ("pw-takeover", "BOLA", "exploit_pw.py", "legit_pw.py"),
        ]
        print("\n== exploit-verification (per defect) ==")
        all_ok = True
        for name, cls, exploit, legit in vulns:
            before = run_script(exploit, VULN) == 0       # succeeds on vulnerable
            after = run_script(exploit, SECURE) != 0      # blocked on secure
            legit_ok = run_script(legit, SECURE) == 0     # legit preserved
            ok = before and after and legit_ok
            all_ok &= ok
            print(f"  [{cls}] {name:12} before={before} after-blocked={after} "
                  f"legit={legit_ok}  -> {'success' if ok else 'FAILED'}")

        print(f"\n  => VAmPI multi-defect verdict: {'success' if all_ok else 'FAILED'} "
              f"({len(vulns)} defects exploit-verified)")
        return 0 if all_ok else 1
    finally:
        print("\n== tearing down ==")
        compose("down", "-v", timeout=120)


if __name__ == "__main__":
    sys.exit(main())
