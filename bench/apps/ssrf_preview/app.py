"""ssrf_preview — SSRF: fetches a user-supplied URL with no validation."""
ALLOWED_HOSTS = {"api.example.com"}

def is_safe_url(url):
    host = url.split("/")[2] if "://" in url else url
    return host in ALLOWED_HOSTS

def fetch_url(url):
    host = url.split("/")[2] if "://" in url else url
    return {"host": host, "internal": host in ("169.254.169.254", "localhost", "127.0.0.1")}

def get_preview(url):
    data = fetch_url(url)        # SSRF: no URL validation on the path
    return data
