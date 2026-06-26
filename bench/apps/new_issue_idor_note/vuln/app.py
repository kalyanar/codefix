NOTES = {1: {"id": 1, "owner_id": 1, "text": "a"}, 2: {"id": 2, "owner_id": 2, "text": "b"}}
_CTX = {"uid": None}
def sign_in(uid): _CTX["uid"] = uid
def current_user_id(): return _CTX["uid"]
def fetch_note(nid): return NOTES.get(nid)
def read_note(nid):
    note = fetch_note(nid)
    return note
