import json
import sys
import urllib.request

FETCHED = []


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen(url, *a, **k):
    FETCHED.append(url.split("/")[2] if "://" in url else url)
    return _Resp()


def _load():
    urllib.request.urlopen = _fake_urlopen      # no real request leaves the machine
    d = sys.argv[sys.argv.index("--app") + 1]
    sys.path.insert(0, d)
    import app
    return app


def main():
    """An allowed public URL still previews."""
    app = _load()
    try:
        r = app.get_preview("http://api.example.com/page")
    except PermissionError:
        print("REGRESSION: allowed url blocked")
        return 1
    print("CONTRACT " + json.dumps(r))
    return 0 if r.get("status") == 200 and FETCHED == ["api.example.com"] else 1


sys.exit(main())
