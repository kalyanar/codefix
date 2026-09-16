"""Order service: one hop between the view and the repository."""
from ..repo import load_order


def order_details(oid):
    order = load_order(oid)
    return order
