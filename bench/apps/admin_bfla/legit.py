import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """An admin still performs the privileged delete."""
    app = _load()
    app.sign_in(2)
    try:
        r = app.admin_delete_account(1)
    except PermissionError:
        print("REGRESSION: admin blocked")
        return 1
    print("CONTRACT " + json.dumps(r))
    return 0 if r and r.get("deleted") == 1 else 1


sys.exit(main())
