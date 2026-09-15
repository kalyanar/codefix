import urllib.request

ALLOWED_HOSTS = {"api.example.com"}


def is_safe_url(url):
    host = url.split("/")[2] if "://" in url else url
    return host in ALLOWED_HOSTS


def fetch_page(url):
    with urllib.request.urlopen(url, timeout=2) as resp:
        return {"url": url, "status": resp.status}


def get_preview(url):
    if not is_safe_url(url):
        raise PermissionError("blocked url")
    data = fetch_page(url)
    return data
