import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


PRIVILEGED = ("is_admin", "role", "is_staff", "is_superuser")


def main():
    """Other privileged fields and mixed payloads must not get through either."""
    payloads = [{"name": "m", "email": "m@x.com", "role": "admin"},
                {"name": "m", "is_staff": True},
                {"email": "m@x.com", "is_superuser": 1, "is_admin": "yes"}]
    for p in payloads:
        app = _load()
        user = app.register(dict(p))
        leaked = [k for k in PRIVILEGED if k in user]
        if leaked:
            print(f"BYPASS: {leaked} set via {p}")
            return 1
    print("all variant attacks blocked")
    return 0


sys.exit(main())
