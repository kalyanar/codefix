import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """Varied attackers (other principal, other object, signed out) must all be blocked."""
    attacks = [(2, 1), (None, 2), (3, 2)]
    for who, target in attacks:
        app = _load()
        app.sign_in(who)
        try:
            rec = app.read_note(target)
        except PermissionError:
            continue
        if rec is not None and rec.get("owner_id") != who:
            print(f"BYPASS: principal {who} read {target}: {rec}")
            return 1
    print("all variant attacks blocked")
    return 0


sys.exit(main())
