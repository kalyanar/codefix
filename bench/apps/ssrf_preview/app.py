"""ssrf_preview — SSRF: fetches a user-supplied URL with no validation.

`get_preview` hands the caller's URL to `fetch_page`, which opens it with the
standard library's `urllib.request.urlopen` — the resolved library symbol the
SSRF sink anchors on. Nothing on the path validates the host, so a caller can
make the server fetch cloud metadata (169.254.169.254) or localhost.
"""
import urllib.request

ALLOWED_HOSTS = {"api.example.com"}


def is_safe_url(url):
    host = url.split("/")[2] if "://" in url else url
    return host in ALLOWED_HOSTS


def fetch_page(url):
    with urllib.request.urlopen(url, timeout=2) as resp:
        return {"url": url, "status": resp.status}


def get_preview(url):
    data = fetch_page(url)        # SSRF: no URL validation on the path
    return data
