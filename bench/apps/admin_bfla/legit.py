"""Legit: an admin invokes the admin delete. Exit 0 => preserved."""
import sys
def main():
    app_dir = sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0, app_dir)
    import app
    app.sign_in(2)  # admin (role=admin)
    try:
        r = app.admin_delete_account(1)
    except PermissionError:
        print("REGRESSION: admin blocked"); return 1
    print("OK: admin performed privileged op", r); return 0 if r and r.get("deleted")==1 else 1
sys.exit(main())
