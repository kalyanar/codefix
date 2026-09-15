import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """Owner reads their own record; prints the response for the contract stage."""
    app = _load()
    app.login(2)
    try:
        rec = app.get_order(2)
    except PermissionError:
        print("REGRESSION: owner blocked")
        return 1
    print("CONTRACT " + json.dumps(rec))
    return 0 if rec is not None and rec.get("user_id") == 2 else 1


sys.exit(main())
