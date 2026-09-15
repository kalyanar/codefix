import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """A signed-in user can still transfer."""
    app = _load()
    app.login(1)
    try:
        r = app.do_transfer(50, 2)
    except PermissionError:
        print("REGRESSION: signed-in transfer blocked")
        return 1
    print("CONTRACT " + json.dumps(r))
    return 0 if r.get("transferred") == 50 else 1


sys.exit(main())
