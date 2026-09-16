_S = {"uid": None}


def current_user():
    return _S["uid"]


BALANCES = {1: 100, 2: 100}


def transfer(amount, to):
    BALANCES[to] = BALANCES.get(to, 0) + amount
    return {"transferred": amount, "to": to}


def do_transfer(amount, to):
    if current_user() is None:
        raise PermissionError("authentication required")
    return transfer(amount, to)
