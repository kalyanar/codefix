import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """A normal registration with only allowed fields still works."""
    app = _load()
    user = app.register({"name": "alice", "email": "a@x.com"})
    print("CONTRACT " + json.dumps(user))
    ok = user.get("name") == "alice" and user.get("email") == "a@x.com"
    return 0 if ok else 1


sys.exit(main())
