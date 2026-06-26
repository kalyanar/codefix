"""library_flat_bola — SAME BOLA defect as library_bola, but FLAT.

The fetch is inlined (no lookup_record helper), so the call-chain topology
differs (callees=0 here vs 1 in library_bola). A topology-hash fingerprint would
MISS this; the facet fingerprint MATCHES it, so the fix transfers from the DB.
"""
RECORDS = {
    1: {"id": 1, "owner_id": 1, "body": "alice"},
    2: {"id": 2, "owner_id": 2, "body": "bob private"},
}
_CTX = {"uid": None}


def sign_in(uid):
    _CTX["uid"] = uid


def current_user_id():
    return _CTX["uid"]


def view_record(rid):
    rec = RECORDS.get(rid)        # inlined sink — FLAT, no helper on the path
    return rec
