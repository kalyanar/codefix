"""Contract conformance: print the owner's legitimate response (stable shape).
The validator runs this on the original AND patched app and compares — the fix
must not alter the legitimate response (fields/types/values)."""
import sys, json
def main():
    d = sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0, d); import app
    app.login(2)                      # owner
    print(json.dumps(app.get_order(2), sort_keys=True))
    return 0
sys.exit(main())
