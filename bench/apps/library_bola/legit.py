"""Legit path for library_bola: owner (uid=2) reads own record (id=2).
Exit 0 => preserved. Exit !=0 => regression."""
import sys


def main() -> int:
    app_dir = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, app_dir)
    import app

    app.sign_in(2)  # owner
    try:
        rec = app.view_record(2)
    except PermissionError:
        print("REGRESSION: owner blocked from own record")
        return 1
    if rec is not None and rec.get("owner_id") == 2:
        print("OK: owner read own record")
        return 0
    print("REGRESSION: owner got empty/denied")
    return 1


if __name__ == "__main__":
    sys.exit(main())
