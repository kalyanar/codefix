"""Legitimate-path check for VAmPI: the owner reads their OWN book.

Must keep working after the fix (differential-behavior half of the validator).

Exit 0  => owner can read own book.
Exit !=0 => the fix broke legitimate access (regression).

Usage: python legit.py --base-url http://localhost:5001
"""
import argparse
import secrets
import sys

import requests


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    sfx = secrets.token_hex(3)
    owner, pw = f"owner_{sfx}", "pw12345678"
    title, secret = f"book_{sfx}", f"SECRET_{sfx}"

    s = requests.Session()
    s.post(f"{base}/users/v1/register",
           json={"username": owner, "password": pw, "email": f"{owner}@example.com"}, timeout=10)
    tok = s.post(f"{base}/users/v1/login",
                 json={"username": owner, "password": pw}, timeout=10).json().get("auth_token")
    s.post(f"{base}/books/v1", json={"book_title": title, "secret": secret},
           headers={"Authorization": f"Bearer {tok}"}, timeout=10)

    r = s.get(f"{base}/books/v1/{title}",
              headers={"Authorization": f"Bearer {tok}"}, timeout=10)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}

    if body.get("secret") == secret:
        print(f"OK: owner read own book secret {body.get('secret')!r}")
        return 0
    print(f"REGRESSION: owner blocked from own book; status={r.status_code} body={body}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
