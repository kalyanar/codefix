# crAPI workshop service (vendored)

- Upstream: https://github.com/OWASP/crAPI
- Commit: b5fc307f3e5f875809b095b771108ef342a33724 (2026-09-09), `VERSION` 1.1.5
- License: Apache License 2.0 (`LICENSE.md`, copied verbatim from upstream)
- Contents: `services/workshop/` (the Python/Django service that holds the
  shop-order BOLA, `GET /workshop/api/shop/orders/<id>`), unmodified, placed at
  the root of this directory.
- Used by: the SAST baselines (`bench/baselines.py`), codefix's scan
  (`bench/live_codefix.py crapi`) and the live harness (`run_crapi.py`), which
  rebuilds the workshop image from codefix's patched copy of this tree.
- Omitted: upstream's `certs/` (a demo TLS private key). The workshop Dockerfile
  copies `./certs`, so `run_crapi.py` generates a throwaway self-signed pair
  before building; no private key is committed.
