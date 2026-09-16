ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}
_S = {"uid": None}


def login(uid):
    _S["uid"] = uid


def current_user_id():
    return _S["uid"]


def get_order(order_id):
    order = ORDERS.get(order_id)
    return order
