"""missing_auth — a sensitive action (transfer) reachable with no authn check."""
_CTX = {"uid": None}
def login(uid): _CTX["uid"] = uid
def current_user(): return _CTX["uid"]

BALANCES = {1: 100, 2: 100}

def transfer(amount, to):
    BALANCES[to] = BALANCES.get(to, 0) + amount
    return {"transferred": amount, "to": to}

def do_transfer(amount, to):
    return transfer(amount, to)     # MISSING AUTH: no authentication on the path
