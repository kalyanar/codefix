"""library_bola — a DIFFERENT codebase with the SAME BOLA shape.

Different names (view_record / lookup_record / rid), different owner field
(owner_id, not user_id), different domain (library records, not shop orders).
Structurally it is the same defect shape, so its fingerprint matches shop_bola's
— which is how the fix template is recalled from the DB and re-rendered here.
"""
RECORDS = {
    1: {"id": 1, "owner_id": 1, "body": "alice notes"},
    2: {"id": 2, "owner_id": 2, "body": "bob private notes"},   # belongs to user 2
}

_CTX = {"uid": None}


def sign_in(uid):
    _CTX["uid"] = uid


def current_user_id():
    return _CTX["uid"]


def lookup_record(rid):
    return RECORDS.get(rid)


def view_record(rid):
    rec = lookup_record(rid)
    return rec
