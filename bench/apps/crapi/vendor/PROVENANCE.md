# crAPI workshop service (vendored subset)

- Upstream: https://github.com/OWASP/crAPI
- Commit: b5fc307f3e5f875809b095b771108ef342a33724 (2026-09-09), `VERSION` 1.1.5
- License: Apache License 2.0 (`LICENSE.md`, copied verbatim from upstream)
- Subset: `services/workshop/` only (the Python/Django service that holds the
  shop-order BOLA, `GET /workshop/api/shop/orders/<id>`). This is the source the
  SAST baselines scan (`bench/baselines.py`).
- Omitted: `services/workshop/certs/` (a demo TLS private key and certificate;
  not source, and a private key in the tree trips secret scanners). No file was
  modified.
- Note: the live exploit (`bench/apps/crapi/run_crapi.py`) runs the upstream
  `crapi/crapi-workshop:latest` image, not this vendored tree, so the two can drift.
