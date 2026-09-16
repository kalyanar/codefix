import json
import sys


def _load():
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    from shop import auth, views
    return auth, views


def main():
    auth, views = _load()
    auth.login(2)
    try:
        order = views.show_order(2)
    except PermissionError:
        print("REGRESSION: owner blocked")
        return 1
    print("CONTRACT " + json.dumps(order))
    return 0 if order and order["user_id"] == 2 else 1


sys.exit(main())
