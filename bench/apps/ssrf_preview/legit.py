import sys
def main():
    d = sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0, d); import app
    try: r = app.get_preview("http://api.example.com/page")
    except PermissionError: print("REGRESSION"); return 1
    return 0 if not r.get("internal") else 1
sys.exit(main())
