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
    """Other internal targets and a userinfo trick must also be refused."""
    for url in ("http://localhost:8080/admin", "http://127.0.0.1/",
                "http://api.example.com@169.254.169.254/latest",
                "http://metadata.google.internal/computeMetadata/v1/"):
        app = _load()
        FETCHED.clear()
        try:
            app.get_preview(url)
        except PermissionError:
            continue
        if FETCHED and FETCHED[0] != "api.example.com":
            print(f"BYPASS: fetched {FETCHED[0]} via {url}")
            return 1
    print("all variant attacks blocked")
    return 0


sys.exit(main())
