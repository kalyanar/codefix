NOTES = {1: {"id": 1, "owner_id": 1, "text": "a"}, 2: {"id": 2, "owner_id": 2, "text": "b"}}
_CTX = {"uid": None}


def sign_in(uid):
    _CTX["uid"] = uid


def current_user_id():
    return _CTX["uid"]


def get_note(note_id):
    return NOTES.get(note_id)


def load_for_view(note_id):
    return get_note(note_id)


def read_note(note_id):
    note = load_for_view(note_id)
    return note
