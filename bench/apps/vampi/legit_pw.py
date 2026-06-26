"""Legit path #2 — the owner updates their OWN password (must still work)."""
import secrets, sys, requests
def main() -> int:
    base = sys.argv[sys.argv.index("--base-url") + 1].rstrip("/")
    sfx = secrets.token_hex(3); owner, pw = f"owner_{sfx}", "pw12345678"
    s = requests.Session()
    s.post(f"{base}/users/v1/register", json={"username": owner, "password": pw, "email": f"{owner}@x.com"}, timeout=10)
    t = s.post(f"{base}/users/v1/login", json={"username": owner, "password": pw}, timeout=10).json().get("auth_token")
    new_pw = "newpw_" + sfx
    s.put(f"{base}/users/v1/{owner}/password", json={"password": new_pw}, headers={"Authorization": f"Bearer {t}"}, timeout=10)
    r = s.post(f"{base}/users/v1/login", json={"username": owner, "password": new_pw}, timeout=10).json()
    if r.get("auth_token"): print("OK: owner changed own password"); return 0
    print("REGRESSION: owner cannot change own password"); return 1
if __name__ == "__main__":
    sys.exit(main())
