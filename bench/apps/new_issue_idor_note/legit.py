import sys
def main():
    d=sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0,d); import app
    app.sign_in(2)
    try: n=app.read_note(2)
    except PermissionError: print("REGRESSION"); return 1
    return 0 if n and n.get("owner_id")==2 else 1
sys.exit(main())
