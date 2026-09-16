"""Session principal (stand-in for flask_login.current_user)."""
_SESSION = {"uid": None}


def login(uid):
    _SESSION["uid"] = uid


def current_user_id():
    return _SESSION["uid"]
