import sys

ORDERS = {1: {"id": 1, "user_id": 1}, 2: {"id": 2, "user_id": 2}}


def run_cmd(cmd):
    return eval(cmd)               # code injection sink


def cli_handler():
    cmd = sys.argv[1]             # CodeQL-recognized source (argv)
    return run_cmd(cmd)           # interprocedural: argv -> eval  (CodeQL flags)


def get_order(order_id):          # BOLA: fetch by id, no ownership check
    return ORDERS.get(order_id)   # CodeQL has no authorization query -> 0
