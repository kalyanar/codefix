"""admin_bfla — Broken Function Level Authorization.

`admin_delete_account` performs a privileged, state-changing operation
(deletes an account) and is reachable by ANY logged-in user — there is no
role/permission check on the path. Detection is name-independent: it keys on
the state-changing op shape + the absence of a role comparison, not on the
function being named "admin_*".
"""
USERS = {1: {"id": 1, "role": "user"}, 2: {"id": 2, "role": "admin"}}
ACCOUNTS = {1: {"id": 1, "balance": 100}, 2: {"id": 2, "balance": 9999}}

_CTX = {"uid": None}


def sign_in(uid):
    _CTX["uid"] = uid


def current_user():
    return USERS.get(_CTX["uid"])


def wipe_account(account_id):
    ACCOUNTS.pop(account_id, None)          # privileged, state-changing op
    return {"deleted": account_id}


def admin_delete_account(account_id):
    return wipe_account(account_id)         # BFLA: no role gate on the path
