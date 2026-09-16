"""Data access layer."""
ORDERS = {
    1: {"id": 1, "user_id": 1, "total": 100, "card_last4": "4242"},
    2: {"id": 2, "user_id": 2, "total": 250, "card_last4": "1881"},
}


def load_order(order_id):
    return ORDERS.get(order_id)
