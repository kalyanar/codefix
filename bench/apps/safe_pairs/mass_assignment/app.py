ALLOWED_FIELDS = {"name", "email"}


def build_user(**kw):
    return dict(kw)


def register(data):
    data = {k: data[k] for k in ALLOWED_FIELDS if k in data}
    user = build_user(**data)
    return user
