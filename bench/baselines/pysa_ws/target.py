ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}

def run_query(q):
    return eval(q)                 # dangerous sink (code execution)

def search_handler(req):           # taint flow: user input -> eval  (Pysa catches)
    q = req
    return run_query(q)

def get_order(order_id):           # BOLA: no ownership check, but NOT a taint->sink
    return ORDERS.get(order_id)    # Pysa has nothing to flag here
