"""mass_assign — Mass Assignment (privilege escalation via unfiltered **kwargs).

`register` spreads a user-supplied dict straight into the user object with no
field allowlist, so an attacker can set fields they shouldn't (e.g. is_admin).
"""
ALLOWED_FIELDS = {"name", "email"}


def build_user(**kw):
    return dict(kw)


def register(data):
    user = build_user(**data)        # MASS ASSIGNMENT: no allowlist on `data`
    return user
