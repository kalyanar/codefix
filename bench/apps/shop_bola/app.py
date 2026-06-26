"""shop_bola — a minimal app with a Broken Object Level Authorization (BOLA).

`get_order` fetches an order by a user-supplied id and returns it with NO
ownership check. Any logged-in user can read any other user's order.

Auth is modelled in-process: `login(uid)` sets the acting principal;
`current_user_id()` reads it. This is the *resolved principal source* the
structural detector anchors on (the stand-in for `flask_login.current_user`).
"""

# in-memory data ------------------------------------------------------------
USERS = {1: {"id": 1, "name": "attacker"}, 2: {"id": 2, "name": "victim"}}
ORDERS = {
    1: {"id": 1, "user_id": 1, "total": 100},
    2: {"id": 2, "user_id": 2, "total": 250},   # belongs to the victim
}

_CURRENT = {"uid": None}


def login(uid):
    _CURRENT["uid"] = uid


def current_user_id():
    return _CURRENT["uid"]


# data access ---------------------------------------------------------------
def get_order_by_id(order_id):
    return ORDERS.get(order_id)


# route ---------------------------------------------------------------------
def get_order(order_id):
    order = get_order_by_id(order_id)
    return order
