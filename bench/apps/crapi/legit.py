"""crAPI legit baseline — owner reads their OWN order (must work).

The captured response is the CONTRACT sample: the harness checks that the owner's
legit order+payment response keeps the expected keys + value types after the fix.
Prints a machine-readable final line:  RESULT {json}
"""
import argparse, json, secrets, sys, requests

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--base-url", required=True)
    b = ap.parse_args().base_url.rstrip("/")
    sfx = secrets.token_hex(3); pw = "Pass123!"; owner = f"o_{sfx}@ex.com"
    requests.post(f"{b}/identity/api/auth/signup",
                  json={"name": f"o{sfx}", "email": owner, "number": "407"+sfx[:7].ljust(7, "0"), "password": pw}, timeout=15)
    t = requests.post(f"{b}/identity/api/auth/login",
                      json={"email": owner, "password": pw}, timeout=15).json().get("token")
    oid = requests.post(f"{b}/workshop/api/shop/orders", json={"product_id": 1, "quantity": 1},
                        headers={"Authorization": f"Bearer {t}"}, timeout=15).json().get("id")
    resp = requests.get(f"{b}/workshop/api/shop/orders/{oid}",
                        headers={"Authorization": f"Bearer {t}"}, timeout=15)
    r = resp.json() if resp.text.strip() else {}
    ok = r.get("order", {}).get("user", {}).get("email") == owner
    result = {"defect": "shop-order", "kind": "legit", "ok": ok,
              "status": resp.status_code, "body": r}
    if ok:
        print("OK: owner read own order")
    else:
        print("REGRESSION:", r)
    print("RESULT " + json.dumps(result))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
