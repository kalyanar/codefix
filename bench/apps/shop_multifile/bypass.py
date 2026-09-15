import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    from shop import auth, views
    return auth, views


def main():
    for who, target in ((2, 1), (None, 2), (7, 1)):
        auth, views = _load()
        auth.login(who)
        try:
            order = views.show_order(target)
        except PermissionError:
            continue
        if order and order["user_id"] != who:
            print(f"BYPASS: {who} read order {target}")
            return 1
    print("all variant attacks blocked")
    return 0


sys.exit(main())
