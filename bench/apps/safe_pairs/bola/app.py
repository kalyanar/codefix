ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}
_S = {"uid": None}


def current_user_id():
    return _S["uid"]


def get_order_by_id(order_id):
    return ORDERS.get(order_id)


def get_order(order_id):
    order = get_order_by_id(order_id)
    if order is not None and order["user_id"] != current_user_id():
        raise PermissionError("not owner")
    return order
