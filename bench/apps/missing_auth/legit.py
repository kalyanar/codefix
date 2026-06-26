import sys
def main():
    d = sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0, d); import app
    app.login(1)
    try: r = app.do_transfer(50, 2)
    except PermissionError: print("REGRESSION"); return 1
    return 0 if r.get("transferred") == 50 else 1
sys.exit(main())
