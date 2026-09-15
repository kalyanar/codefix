"""Def-use taint and principal closures over the function IR (paper §III.E).

A user-controlled value rarely reaches the sink directly (``oid = order_id;
key = oid; fetch(key)``). Taint is seeded at request-derived values — an entry
point's scalar parameters and framework request accessors — and propagated to a
fixpoint over def-use: every name bound by a statement that reads a tainted name
becomes tainted (assignment chains, attributes, call returns). Each tainted
name carries the *role* of its origin (path parameter, query parameter, body
field, header), which becomes the fingerprint's ``source_role`` facet.
Interprocedural flow into helpers is handled by the engine, which binds tainted
call arguments to the callee's parameters and re-seeds this closure there.

The principal closure is the dual: names derived from the authenticated
identity (``current_user``, ``request.user``, a token validator). A verified
identity is not attacker-chosen, so it never propagates taint.
"""
from __future__ import annotations

from .ir import FunctionBody

# framework request accessors -> source role
REQUEST_ACCESSORS = (
    ("request.view_args", "path_param"), ("request.match_info", "path_param"),
    ("request.path_params", "path_param"),
    ("request.args", "query_param"), ("request.GET", "query_param"),
    ("request.query_params", "query_param"), ("request.values", "query_param"),
    ("request.json", "body_field"), ("request.get_json", "body_field"),
    ("request.form", "body_field"), ("request.data", "body_field"),
    ("request.POST", "body_field"), ("request.files", "body_field"),
    ("request.body", "body_field"),
    ("request.headers", "header"), ("request.META", "header"),
    ("request.cookies", "header"), ("request.COOKIES", "header"),
)
REQUEST_OBJECTS = {"request", "req", "self", "cls"}
ROLE_ORDER = ("path_param", "query_param", "body_field", "header", "param")

PRINCIPAL_ANCHORS = frozenset({
    "current_user_id", "current_user", "get_current_user", "request_user",
    "request.user", "g.user", "get_jwt_identity", "token_validator",
    "get_current_active_user", "authenticated_userid",
})


def accessor_roles(tokens) -> set[str]:
    out = set()
    for t in tokens:
        for prefix, role in REQUEST_ACCESSORS:
            if t == prefix or t.startswith(prefix + "."):
                out.add(role)
    return out


def has_anchor(tokens, anchors) -> bool:
    """Leaf-name match, robust to dotted access (``auth.assert_owns``)."""
    for t in tokens:
        if t in anchors:
            return True
        if "." in t:
            if t.rsplit(".", 1)[-1] in anchors:
                return True
            if any("." in a and t.startswith(a + ".") for a in anchors):
                return True
    return False


def principal_closure(body: FunctionBody, anchors=PRINCIPAL_ANCHORS, seeds=()) -> set[str]:
    """Names that hold the authenticated identity on every definition (a must
    analysis): ``book`` bound from a principal-scoped query in one branch and from
    a caller-chosen title in another is NOT principal-derived. `seeds` are
    parameters an authentication decorator injects (``user``)."""
    defs: dict[str, list] = {}
    for s in body.real():
        for w in s.writes:
            defs.setdefault(w, []).append(s)
    names: set[str] = {n for n in seeds if n not in defs}
    changed = True
    while changed:
        changed = False
        for name, ds in defs.items():
            if name in names:
                continue
            if all(has_anchor(d.tokens, anchors) or (d.reads & names) for d in ds):
                names.add(name)
                changed = True
    return names


def taint_closure(body: FunctionBody, seeds: dict[str, set[str]],
                  principal: set[str] | None = None,
                  anchors=PRINCIPAL_ANCHORS) -> dict[str, set[str]]:
    """name -> set of source roles, to a fixpoint."""
    principal = principal or set()
    roles = {k: set(v) for k, v in seeds.items()}
    changed = True
    while changed:
        changed = False
        for s in body.real():
            if not s.writes or has_anchor(s.tokens, anchors):
                continue
            src: set[str] = set()
            for r in s.reads:
                if r in roles and r not in principal:
                    src |= roles[r]
            src |= accessor_roles(s.tokens)
            if not src:
                continue
            for w in s.writes:
                if w in principal:
                    continue
                before = len(roles.get(w, ()))
                roles.setdefault(w, set()).update(src)
                if len(roles[w]) != before:
                    changed = True
    return roles


def expr_roles(reads, tokens, taint: dict[str, set[str]]) -> set[str]:
    out: set[str] = set()
    for r in reads:
        if r in taint:
            out |= taint[r]
    return out | accessor_roles(tokens)


def pick_role(roles: set[str]) -> str:
    for r in ROLE_ORDER:
        if r in roles:
            return r
    return "param"
