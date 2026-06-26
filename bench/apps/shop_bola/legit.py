"""Legitimate-path check for shop_bola.

The owner (uid=2) reads their own order (id=2). This MUST keep working after
the fix — it is the differential-behavior half of the validator.

Exit 0  => legitimate access works.
Exit !=0 => the patch broke legitimate behavior (a regression).

Usage: python legit.py --app <dir-containing-app.py>
"""
import sys


def main() -> int:
    app_dir = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, app_dir)
    import app

    app.login(2)  # owner
    try:
        order = app.get_order(2)  # own order
    except PermissionError:
        print("REGRESSION: owner blocked from own order")
        return 1
    if order is not None and order.get("user_id") == 2:
        print("OK: owner read own order")
        return 0
    print("REGRESSION: owner got empty/denied")
    return 1


if __name__ == "__main__":
    sys.exit(main())
