import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """Unauthenticated transfers with other amounts / recipients must be refused."""
    for amount, to in ((1, 1), (10_000, 3), (0, 2)):
        app = _load()
        try:
            r = app.do_transfer(amount, to)
        except PermissionError:
            continue
        if r.get("transferred") == amount:
            print(f"BYPASS: unauthenticated transfer of {amount} to {to}")
            return 1
    print("all variant attacks blocked")
    return 0


sys.exit(main())
