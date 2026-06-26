"""crAPI legit baseline — owner reads their OWN order (must work)."""
import secrets, sys, requests
def main() -> int:
    b = sys.argv[sys.argv.index("--base-url") + 1].rstrip("/")
    sfx = secrets.token_hex(3); pw = "Pass123!"; owner = f"o_{sfx}@ex.com"
    requests.post(f"{b}/identity/api/auth/signup", json={"name": f"o{sfx}", "email": owner, "number": "407"+sfx[:7].ljust(7,"0"), "password": pw}, timeout=10)
    t = requests.post(f"{b}/identity/api/auth/login", json={"email": owner, "password": pw}, timeout=10).json().get("token")
    oid = requests.post(f"{b}/workshop/api/shop/orders", json={"product_id":1,"quantity":1}, headers={"Authorization": f"Bearer {t}"}, timeout=10).json().get("id")
    r = requests.get(f"{b}/workshop/api/shop/orders/{oid}", headers={"Authorization": f"Bearer {t}"}, timeout=10).json()
    if r.get("order", {}).get("user", {}).get("email") == owner:
        print("OK: owner read own order"); return 0
    print("REGRESSION:", r); return 1
if __name__ == "__main__":
    sys.exit(main())
