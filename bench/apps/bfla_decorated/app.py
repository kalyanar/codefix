"""bfla_decorated — demonstrates UP-THE-CHAIN dominance.

`delete_account_safe` is protected by the @admin_required decorator (the guard
lives ABOVE the function, up the chain) and must NOT be flagged.
`delete_account_unsafe` has the same privileged op with no dominating guard and
MUST be flagged. The detector recognises the decorator's role comparison as a
dominator regardless of the decorator's name (it scans the decorator body).
"""
USERS = {1: {"id": 1, "role": "user"}, 2: {"id": 2, "role": "admin"}}
ACCOUNTS = {1: {"id": 1}, 2: {"id": 2}}
_CTX = {"uid": None}


def sign_in(uid):
    _CTX["uid"] = uid


def current_user():
    return USERS.get(_CTX["uid"])


def admin_required(fn):
    def wrapper(*a, **k):
        if current_user() is None or current_user().get("role") != "admin":
            raise PermissionError("forbidden")
        return fn(*a, **k)
    return wrapper


@admin_required
def delete_account_safe(account_id):
    ACCOUNTS.pop(account_id, None)        # privileged op, but dominated by decorator
    return {"deleted": account_id}


def delete_account_unsafe(account_id):
    ACCOUNTS.pop(account_id, None)        # privileged op, NO dominating guard
    return {"deleted": account_id}
