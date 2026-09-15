"""HTTP-facing views. `show_order` hands a caller-chosen id to the service
layer, which reads it from the repository in a third module — nothing on that
cross-file path checks that the order belongs to the caller."""
from .services import orders


def show_order(order_id):
    order = orders.order_details(order_id)
    return order
