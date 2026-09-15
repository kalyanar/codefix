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
    app.sign_in(2)
    try:
        rec = app.view_record(2)
    except PermissionError:
        print("REGRESSION: owner blocked")
        return 1
    print("CONTRACT " + json.dumps(rec))
    return 0 if rec is not None and rec.get("owner_id") == 2 else 1


sys.exit(main())
