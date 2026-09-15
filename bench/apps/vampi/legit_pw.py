"""Legit path #2 — the owner updates their OWN password (must still work).

The captured update-password response is the CONTRACT sample for this defect:
the harness checks status 204 and (if a body is present) keys+types.
Prints a machine-readable final line:  RESULT {json}
"""
import argparse, json, secrets, sys, requests

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    sfx = secrets.token_hex(3); owner, pw = f"owner_{sfx}", "pw12345678"
    s = requests.Session()
    s.post(f"{base}/users/v1/register", json={"username": owner, "password": pw, "email": f"{owner}@x.com"}, timeout=10)
    t = s.post(f"{base}/users/v1/login", json={"username": owner, "password": pw}, timeout=10).json().get("auth_token")
    new_pw = "newpw_" + sfx
    pr = s.put(f"{base}/users/v1/{owner}/password", json={"password": new_pw},
               headers={"Authorization": f"Bearer {t}"}, timeout=10)
    try:
        pbody = pr.json() if pr.text.strip() else {}
    except Exception:
        pbody = {}
    r = s.post(f"{base}/users/v1/login", json={"username": owner, "password": new_pw}, timeout=10).json()
    ok = bool(r.get("auth_token"))
    result = {"defect": "pw-takeover", "kind": "legit", "ok": ok,
              "status": pr.status_code, "body": pbody}
    if ok:
        print("OK: owner changed own password")
    else:
        print("REGRESSION: owner cannot change own password")
    print("RESULT " + json.dumps(result))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
