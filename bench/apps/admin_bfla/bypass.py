import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """Signed-out callers and a user targeting another account must be blocked."""
    for who, target in ((None, 1), (1, 2), (99, 2)):
        app = _load()
        app.sign_in(who)
        try:
            r = app.admin_delete_account(target)
        except PermissionError:
            continue
        if r and r.get("deleted") == target:
            print(f"BYPASS: principal {who} deleted account {target}")
            return 1
    print("all variant attacks blocked")
    return 0


sys.exit(main())
