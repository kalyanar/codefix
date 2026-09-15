USERS = {1: {"id": 1, "role": "user"}, 2: {"id": 2, "role": "admin"}}
ACCOUNTS = {1: {"id": 1}, 2: {"id": 2}}
_S = {"uid": None}


def current_user():
    return USERS.get(_S["uid"])


def wipe_account(account_id):
    ACCOUNTS.pop(account_id, None)
    return {"deleted": account_id}


def admin_delete_account(account_id):
    if current_user() is None or current_user().get("role") != "admin":
        raise PermissionError("forbidden")
    return wipe_account(account_id)
