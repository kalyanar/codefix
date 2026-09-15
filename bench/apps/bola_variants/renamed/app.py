ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}
_S = {"uid": None}


def login(uid):
    _S["uid"] = uid


def current_user_id():
    return _S["uid"]


def q(z9):
    return ORDERS.get(z9)


def h(k):
    x = q(k)
    return x
