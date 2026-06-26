"""Legit: a normal registration with only allowed fields must still work."""
import sys
def main():
    d = sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0, d); import app
    user = app.register({"name": "alice", "email": "a@x.com"})
    if user.get("name") == "alice" and "is_admin" not in user:
        print("OK: normal registration", user); return 0
    print("REGRESSION:", user); return 1
sys.exit(main())
