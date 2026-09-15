"""The generic detection engine (paper §III.E–F, Alg. 1–2).

Every defect class — the five built-ins included — is a declarative
`DetectorSpec`: a *sink matcher* (which operation is dangerous), a *missing
guard* class (which check would have to dominate it), a *search direction*
over the call graph, and a fix template. The engine runs a spec against any
`CallGraphProvider` (the Python CodeMap, or a SCIP-derived graph); it reads only
the provider's call edges, decorator edges and per-function statement IR.

Detection (Alg. 1) is dominated taint-reachability:

    S_c(s)  ∧  T_c(s)  ∧  ¬∃ g : G_c(g) ∧ dom(g, s)

  * taint T_c: request-derived values at an entry point, propagated to a
    fixpoint over def-use and bound into helpers along resolved call edges up to
    ``depth`` hops, so ``handler -> service -> fetch`` is one flow;
  * mitigation (Alg. 2): a bounded search, in the spec's direction, for a
    *denying* guard of class c that *dominates* the exposure — its own body,
    helpers it calls before the exposure (callees), and the decorators and
    callers that wrap it (callers). A guard in a skippable branch, a check that
    only logs, or a check placed after the data has already escaped does not
    count. Guard recognition keys on shapes and resolved principal/role/authn
    symbols, never on the guard helper's name, so ``gate()`` counts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ir import EXIT
from .taint import (PRINCIPAL_ANCHORS, REQUEST_OBJECTS, accessor_roles, expr_roles,
                    has_anchor, pick_role, principal_closure, taint_closure)

# --- controlled vocabulary ----------------------------------------------------
SINK_CATEGORIES = ("object_read", "outbound_fetch", "field_write",
                   "privileged_mutation", "sensitive_action")
GUARD_CLASSES = ("ownership", "role", "authn", "url_validation", "field_allowlist")
SOURCE_ROLES = ("path_param", "query_param", "body_field", "header", "param", "none")
FIX_LOCI = ("handler", "helper", "decorator")
FLOWS = ("param_to_sink", "privileged_function")
DIRECTIONS = ("callees", "callers", "callers_and_self", "both")
# the spec-language constants shown in the paper / site (``search = UP``)
UP, DOWN, BOTH, CALLERS = "callers_and_self", "callees", "both", "callers"

LEGACY = {  # earlier vocabulary, accepted on load so stored catalogs keep working
    "data_access_by_id": "object_read", "url_fetch": "outbound_fetch",
    "model_write": "field_write", "sensitive_op": "sensitive_action",
    "route_param": "path_param", "request_body": "body_field",
    "sink_local": "handler", "entry_local": "handler",
    "privileged_op": "privileged_function", "up": UP, "down": DOWN,
}
PRIVILEGED_CATEGORIES = {"privileged_mutation", "sensitive_action"}


def _norm(v):
    return LEGACY.get(v, v) if isinstance(v, str) else v


# --- anchors (resolved framework / library symbols) ---------------------------
ROLE_ANCHORS = frozenset({"role", "roles", "is_admin", "admin", "is_staff",
                          "is_superuser", "permissions", "has_perm", "has_role"})
AUTHN_ANCHORS = frozenset({"current_user", "current_user_id", "get_current_user",
                           "token_validator", "require_auth", "is_authenticated",
                           "request.user", "get_jwt_identity", "verify_jwt_in_request"})
# knowing the object's own secret is an object-level check (login, reset flows)
CREDENTIAL_ANCHORS = frozenset({"password", "check_password", "verify_password",
                                "check_password_hash", "password_hash", "verify_otp"})
OWNERSHIP_CALLS = frozenset({"assert_owns", "check_object_permissions", "verify_owner",
                             "require_owner", "has_object_permission"})
DECORATOR_ANCHORS = {
    "role": frozenset({"admin_required", "requires_admin", "requires_role",
                       "roles_required", "permission_required", "staff_member_required",
                       "user_passes_test"}),
    "authn": frozenset({"login_required", "jwt_required", "token_required",
                        "auth_required", "authentication_required"}),
    "ownership": frozenset(),
    "url_validation": frozenset(),
    "field_allowlist": frozenset(),
}
# outbound-fetch sinks: resolved library symbols, not helper names
FETCH_SYMBOLS = frozenset({
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve",
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "requests.head", "requests.request", "httpx.get", "httpx.post", "httpx.request",
    "httpx.stream", "urllib3.request", "aiohttp.request", "pycurl.Curl",
})
DATA_READ_LEAVES = frozenset({"get", "get_or_404", "first_or_404", "filter_by", "filter",
                              "find", "find_one", "find_by_id", "fetch", "one",
                              "one_or_none", "lookup", "retrieve", "__getitem__",
                              "select", "load"})
DATA_READ_REGEX = re.compile(r"^(get|fetch|find|load|lookup|read|query|select|retrieve)(_|$)")
NON_DATA_RECEIVERS = ("os", "sys", "json", "re", "math", "logging", "logger", "config",
                      "app.config", "settings", "session", "cache", "environ", "headers",
                      "kwargs", "kw", "params", "str", "dict", "list")
MUTATION_LEAVES = frozenset({"pop", "remove", "delete", "drop", "clear", "destroy",
                             "purge", "delete_one", "delete_many", "truncate"})
SENSITIVE_REGEX = re.compile(r"^(transfer|send_money|charge|payout|wire|place_order|"
                             r"withdraw|refund|pay)(_|$)")
AUTH_DECORATOR_RX = re.compile(r"(auth|login|jwt|token)", re.I)
PRINCIPAL_PARAMS = frozenset({"user", "current_user", "request_user", "principal",
                              "identity", "auth_user"})
ROUTE_LEAVES = {"route", "get", "post", "put", "patch", "delete", "api_route",
                "websocket", "path", "re_path"}


# --- spec language ------------------------------------------------------------
@dataclass(frozen=True)
class SinkMatcher:
    """What marks the dangerous operation: call names, a name regex, a receiver
    regex, resolved library symbols, and which argument must carry taint."""
    category: str
    names: frozenset | None = None
    name_regex: str | None = None
    receiver_regex: str | None = None
    symbols: frozenset | None = None
    arg: str | None = None


def call(*names: str, arg: str | None = None, category: str = "object_read",
         receiver: str | None = None, regex: str | None = None) -> SinkMatcher:
    """``sink = call("get_note", arg="note_id")``."""
    return SinkMatcher(category, frozenset(names) or None, regex, receiver, None, arg)


def symbol(*symbols: str, arg: str | None = None,
           category: str = "outbound_fetch") -> SinkMatcher:
    """``sink = symbol("requests.get", arg="url")`` — a resolved library symbol."""
    return SinkMatcher(category, None, None, None, frozenset(symbols), arg)


@dataclass(init=False)
class DetectorSpec:
    """A defect class as data. Accepts the positional form
    ``DetectorSpec(issue_class, flow, transform_id, source_role, sink_category,
    missing_guard_class, fix_locus, decorator_anchors, call_anchors, direction,
    depth)`` and the keyword form ``DetectorSpec(issue_class=..., sink=call(...),
    missing_guard=..., search=UP, fix_template=...)``. ``source_role`` and
    ``fix_locus`` left unset are read off the detected path."""
    issue_class: str
    flow: str
    transform_id: str
    source_role: str | None
    sink_category: str
    missing_guard_class: str
    fix_locus: str | None
    decorator_anchors: frozenset | None
    call_anchors: frozenset | None
    direction: str
    depth: int
    sink: SinkMatcher | None

    def __init__(self, issue_class, flow=None, transform_id=None, source_role=None,
                 sink_category=None, missing_guard_class=None, fix_locus=None,
                 decorator_anchors=None, call_anchors=None, direction=BOTH, depth=2,
                 *, sink=None, missing_guard=None, search=None, fix_template=None):
        self.issue_class = issue_class
        self.sink = sink
        self.sink_category = _norm(sink.category if sink is not None else sink_category)
        self.missing_guard_class = _norm(missing_guard or missing_guard_class)
        self.transform_id = fix_template or transform_id
        self.direction = _norm(search or direction)
        self.depth = depth
        self.source_role = _norm(source_role) if source_role not in (None, "param") else source_role
        self.fix_locus = _norm(fix_locus)
        self.decorator_anchors = decorator_anchors
        self.call_anchors = call_anchors
        self.flow = _norm(flow) if flow else (
            "privileged_function" if self.sink_category in PRIVILEGED_CATEGORIES
            else "param_to_sink")


# --- findings -------------------------------------------------------------------
@dataclass
class Level:
    """One function on the entry -> sink path."""
    fqname: str
    stmt: int                 # statement that leads down (or the sink statement)
    lineno: int
    bound: str | None         # name bound to that statement's result, if any
    call: object = None       # the CallSite
    tainted: tuple = ()       # tainted names read by that call


@dataclass
class Finding:
    issue_class: str
    func: str
    sink_lineno: int
    sink_assign_target: str
    tainted_args: list
    sink_src: str
    file_path: str
    owner_field: str = "user_id"
    transform_id: str = "insert_ownership_guard"
    source_role: str = ""
    sink_category: str = ""
    missing_guard_class: str = ""
    fix_locus: str = ""
    fqname: str = ""
    sink_file: str = ""
    path: list = field(default_factory=list)       # [Level]
    entry_lineno: int = 0
    framework: str = "none"


# --- helpers ----------------------------------------------------------------
def _route_path_params(g, fq) -> set[str]:
    out = set()
    for d in g.decorators_of(fq):
        if d.decorator.rsplit(".", 1)[-1] in ROUTE_LEAVES:
            for a in d.args:
                if isinstance(a, str):
                    out |= set(re.findall(r"<(?:[^:<>]+:)?(\w+)>", a))
                    out |= set(re.findall(r"\{(\w+)(?::[^}]*)?\}", a))
    return out


def injected_principals(g, fq) -> set[str]:
    """Parameters an authentication decorator supplies (``@jwt_auth_required``
    passing ``user``) hold the principal, not caller-chosen input."""
    fn = g.functions.get(fq)
    if fn is None or not any(AUTH_DECORATOR_RX.search(d) for d in fn.decorators):
        return set()
    return set(fn.params) & PRINCIPAL_PARAMS


# classes whose methods the framework calls with its own objects, not request input
FRAMEWORK_CALLBACK_BASES = re.compile(r"(Serializer|Model|Form|Admin|Field|Migration|TestCase|"
                                      r"AppConfig|Command|Middleware)$")


def _callback_method(g, fn) -> bool:
    if not fn.parent_class:
        return False
    cls = g.classes.get(f"{fn.module}.{fn.qualname.rsplit('.', 1)[0]}")
    if cls is None:
        return False
    import ast
    return any(FRAMEWORK_CALLBACK_BASES.search(ast.unparse(b)) for b in cls.bases)


def entries(g) -> list[str]:
    """Entry points: route-decorated functions and functions no one calls
    (framework callbacks on serializers/models/forms excluded)."""
    out = []
    for fq, fn in g.functions.items():
        if fn.enclosing is not None or _callback_method(g, fn):
            continue
        routed = any(d.decorator.rsplit(".", 1)[-1] in ROUTE_LEAVES for d in g.decorators_of(fq))
        if routed or not g.edges_to(fq):
            out.append(fq)
    return out


def _entry_seeds(g, fq) -> dict[str, set[str]]:
    fn = g.functions[fq]
    path_params = _route_path_params(g, fq)
    injected = injected_principals(g, fq)
    return {p: {"path_param" if p in path_params else "param"}
            for p in fn.params if p not in REQUEST_OBJECTS and p not in injected}


def _bind(callsite, callee, taint) -> dict[str, set[str]]:
    seeds: dict[str, set[str]] = {}
    params = callee.params
    for i, (reads, toks) in enumerate(zip(callsite.arg_reads, callsite.arg_tokens)):
        roles = expr_roles(reads, toks, taint)
        if roles and i < len(params):
            seeds[params[i]] = roles
    for kw, reads in callsite.kw_reads.items():
        roles = expr_roles(reads, callsite.kw_tokens.get(kw, ()), taint)
        if roles and kw in params:
            seeds[kw] = roles
    return seeds


def _receiver_base(recv: str) -> str:
    return recv.split(".", 1)[0] if recv else ""


def _call_arg_roles(c, taint, arg: str | None):
    """-> (roles, tainted names, tokens) over the arguments a sink cares about."""
    if arg and arg in c.kw_reads:
        pairs = [(c.kw_reads[arg], c.kw_tokens.get(arg, frozenset()))]
    elif arg in ("url", None) or not c.kw_reads:
        pairs = list(zip(c.arg_reads, c.arg_tokens)) + \
            [(c.kw_reads[k], c.kw_tokens.get(k, frozenset())) for k in c.kw_reads]
    else:
        pairs = list(zip(c.arg_reads, c.arg_tokens))
    roles, names, toks = set(), set(), set()
    for reads, tk in pairs:
        roles |= expr_roles(reads, tk, taint)
        names |= {r for r in reads if r in taint}
        toks |= set(tk)
    return roles, sorted(names), toks


# --- sink matchers: (graph, fq, body, taint, principal, spec) -> [hit] ----------
@dataclass
class _Hit:
    stmt: int
    lineno: int
    call: object
    bound: str | None
    roles: set
    tainted: list
    src: str


def _exposed(body, s, bound) -> bool:
    """An object read matters when the object — or a value built from it (a
    response dict) — is returned, written through, or handed to a helper."""
    if s.kind == "return":
        return True
    if not bound:
        return False
    derived = {bound}
    changed = True
    while changed:
        changed = False
        for t in body.real():
            if t.id != s.id and t.reads & derived and t.writes - derived:
                derived |= t.writes
                changed = True
    return any(t.returns_value_reads & derived or t.store_bases & derived
               or any(c.all_reads() & derived for c in t.calls if c.callee_fqname)
               for t in body.real() if t.id != s.id)


def _bound(s):
    return next(iter(s.writes)) if s.kind == "assign" and len(s.writes) == 1 else None


OWNER_ATTR_RX = re.compile(r"^(user|owner|author|account|customer|tenant|created_by|vehicle)(_id)?$")


def _unowned_model(g, receiver: str) -> bool:
    """A model class defined in this codebase with no owner-like field (a public
    catalog such as ``Product``) cannot be the object of a BOLA."""
    import ast
    base = receiver.split(".")[0] if receiver else ""
    classes = [c for fq, c in g.classes.items() if fq.rsplit(".", 1)[-1] == base]
    if not classes or re.match(r"^(User|Account|Profile|Customer)", base):
        return False
    for cls in classes:
        for n in cls.body:
            targets = n.targets if isinstance(n, ast.Assign) else \
                [n.target] if isinstance(n, ast.AnnAssign) else []
            if any(isinstance(t, ast.Name) and OWNER_ATTR_RX.match(t.id) for t in targets):
                return False
    return True


def _sink_object_read(g, fq, body, taint, principal, spec):
    m = spec.sink
    out = []
    params = set(g.functions[fq].params)
    for s, c in body.calls():
        if c.callee_fqname and not (m and m.names):
            continue                       # a helper in this codebase: descend instead
        leaf = c.leaf
        if m and m.names:
            if leaf not in m.names and c.callee_name not in m.names:
                continue
        elif not (leaf in DATA_READ_LEAVES or DATA_READ_REGEX.match(leaf)):
            continue
        base = _receiver_base(c.receiver)
        if c.receiver and (base in taint or base in params or base in REQUEST_OBJECTS
                           or base in principal or c.receiver.startswith(NON_DATA_RECEIVERS)
                           or accessor_roles({c.receiver})):
            continue
        if m and m.receiver_regex and not re.search(m.receiver_regex, c.receiver or ""):
            continue
        if not (m and m.names) and _unowned_model(g, c.receiver):
            continue
        roles, names, toks = _call_arg_roles(c, taint, m.arg if m else None)
        if not roles:
            continue
        if has_anchor(toks, PRINCIPAL_ANCHORS) or (c.all_reads() & principal):
            continue                       # ownership-scoped query (``user=request.user``)
        if not _exposed(body, s, _bound(s)):
            continue                       # value never leaves (returned) or is written through
        out.append(_Hit(s.id, c.lineno, c, _bound(s), roles, names,
                        f"{c.callee_name}({', '.join(names)})"))
    return out


def _sink_outbound_fetch(g, fq, body, taint, principal, spec):
    m = spec.sink
    symbols = (m.symbols if m and m.symbols else FETCH_SYMBOLS)
    out = []
    for s, c in body.calls():
        hit = (c.callee_symbol in symbols) or bool(m and m.names and c.leaf in m.names)
        if not hit:
            continue
        roles, names, _ = _call_arg_roles(c, taint, m.arg if m else "url")
        if roles:
            out.append(_Hit(s.id, c.lineno, c, _bound(s), roles, names,
                            f"{c.callee_symbol or c.callee_name}({', '.join(names)})"))
    return out


def _sink_field_write(g, fq, body, taint, principal, spec):
    out = []
    for s, c in body.calls():
        star = sorted(n for n in c.star_kw if n in taint)
        if star and (not spec.sink or not spec.sink.names or c.leaf in spec.sink.names):
            roles = set().union(*(taint[n] for n in star))
            out.append(_Hit(s.id, c.lineno, c, _bound(s), roles, star,
                            f"{c.callee_name}(**{star[0]})"))
    return out


def _sink_privileged_mutation(g, fq, body, taint, principal, spec):
    m = spec.sink
    out = []
    for s in body.real():
        if s.kind == "delete":
            out.append(_Hit(s.id, s.lineno, None, None, set(), [], "del"))
            continue
        for c in s.calls:
            if c.callee_fqname:
                continue
            names = m.names if m and m.names else MUTATION_LEAVES
            if c.leaf not in names:
                continue
            base = _receiver_base(c.receiver)
            if not c.receiver or base in body_locals(body) or base in REQUEST_OBJECTS:
                continue
            out.append(_Hit(s.id, c.lineno, c, None, set(), [], c.callee_name))
    return out


def _sink_sensitive_action(g, fq, body, taint, principal, spec):
    m = spec.sink
    rx = re.compile(m.name_regex) if m and m.name_regex else SENSITIVE_REGEX
    out = []
    for s, c in body.calls():
        if (m and m.names and c.leaf in m.names) or rx.match(c.leaf):
            out.append(_Hit(s.id, c.lineno, c, None, set(), [], c.callee_name))
    return out


def body_locals(body) -> set[str]:
    out: set[str] = set()
    for s in body.real():
        out |= s.writes
    return out


SINK_MATCHERS = {
    "object_read": _sink_object_read,
    "outbound_fetch": _sink_outbound_fetch,
    "field_write": _sink_field_write,
    "privileged_mutation": _sink_privileged_mutation,
    "sensitive_action": _sink_sensitive_action,
}


# --- guard recognition (G_c) --------------------------------------------------
class _Ctx:
    def __init__(self, g, spec):
        self.g, self.spec = g, spec
        self._principal: dict[str, set] = {}

    def principal(self, fq):
        if fq not in self._principal:
            self._principal[fq] = principal_closure(self.g.body(fq), self.principal_anchors(),
                                                    injected_principals(self.g, fq))
        return self._principal[fq]

    def principal_anchors(self):
        if self.spec.missing_guard_class == "ownership" and self.spec.call_anchors is not None:
            return frozenset(self.spec.call_anchors)
        return PRINCIPAL_ANCHORS

    def class_anchors(self):
        cls = self.spec.missing_guard_class
        if self.spec.call_anchors is not None:
            return frozenset(self.spec.call_anchors)
        return {"role": ROLE_ANCHORS, "authn": AUTHN_ANCHORS,
                "ownership": PRINCIPAL_ANCHORS}.get(cls, frozenset())

    def guard_calls(self):
        cls = self.spec.missing_guard_class
        if self.spec.call_anchors is not None:
            return frozenset(self.spec.call_anchors)
        return OWNERSHIP_CALLS if cls == "ownership" else frozenset()

    def decorator_anchors(self):
        if self.spec.decorator_anchors is not None:
            return frozenset(self.spec.decorator_anchors)
        return DECORATOR_ANCHORS.get(self.spec.missing_guard_class, frozenset())

    def helper_reads_principal(self, fqs, depth=1) -> bool:
        for fq in fqs:
            if fq and fq in self.g.functions:
                b = self.g.body(fq)
                if any(has_anchor(s.tokens | s.test_tokens, self.principal_anchors())
                       for s in b.real()):
                    return True
        return False


def _g_ownership(ctx, fq, s, taint) -> bool:
    """A denial test comparing something against the authenticated principal
    (or calling a helper that reads it, or an allow-listed ownership check)."""
    principal = _principal_at(ctx, fq, s)
    if has_anchor(s.test_tokens, ctx.guard_calls()):
        return True
    called = {c.callee_name.split(".")[0] for c in s.test_calls if c.leaf != "__getitem__"}
    reads_principal = has_anchor(s.test_tokens, ctx.principal_anchors()) or \
        bool(s.test_reads & principal) or \
        ctx.helper_reads_principal([c.callee_fqname for c in s.test_calls])
    other = s.test_reads - principal - called - set(ctx.principal_anchors())
    # an identity comparison (==, !=, is, in) or a helper verdict — not a
    # quantity check like ``credit < price`` that merely involves the principal
    identity = bool(s.test_ops & {"eq", "ne", "is", "isnot", "in", "notin"}) or \
        any(c.callee_fqname for c in s.test_calls)
    if reads_principal and has_anchor(s.test_tokens, ROLE_ANCHORS):
        return True                   # a privileged-principal gate (``if user.admin``)
    if s.test_compares and s.test_reads & set(taint) and _checks_stored_secret(s, taint):
        return True                   # the caller proved knowledge of the object's secret
    return reads_principal and bool(other) and identity


def _principal_at(ctx, fq, s) -> set[str]:
    """Names read by `s` whose every reaching definition holds the principal —
    flow-sensitive, so ``user`` (injected) is the principal at a guard placed
    before a later ``user = order.user``."""
    g = ctx.g
    body = g.body(fq)
    closure = ctx.principal(fq)
    seeds = injected_principals(g, fq)
    params = set(g.functions[fq].params)
    anchors = ctx.principal_anchors()
    out = set()
    for n in s.test_reads | s.reads:
        reaching, from_entry = body.reaching_defs(n, s.id)
        if not reaching and not from_entry:
            continue
        if from_entry and n in params and n not in seeds:
            continue
        if all(has_anchor(d.tokens, anchors) or (d.reads & closure) for d in reaching) \
                and (reaching or n in seeds):
            out.add(n)
    return out | (closure & (s.test_reads | s.reads) - {n for n in s.test_reads | s.reads
                                                         if n in params and n not in seeds})


def _checks_stored_secret(s, taint) -> bool:
    """The test reads a secret stored on a (non-attacker) object — ``user.password``
    — or calls a password-verification routine."""
    for t in s.test_tokens:
        if "." in t:
            base, leaf = t.split(".", 1)[0], t.rsplit(".", 1)[-1]
            if leaf in CREDENTIAL_ANCHORS and not base.startswith("request"):
                return True
    return any(c.leaf.startswith(("check_password", "verify_password")) for c in s.test_calls)


def _g_role(ctx, fq, s, taint) -> bool:
    return has_anchor(s.test_tokens, ctx.class_anchors())


def _g_authn(ctx, fq, s, taint) -> bool:
    return has_anchor(s.test_tokens, ctx.class_anchors())


def _g_url_validation(ctx, fq, s, taint) -> bool:
    """A comparison or validator call over the tainted URL."""
    return s.test_compares and bool(s.test_reads & set(taint))


def _g_field_allowlist(ctx, fq, s, taint) -> bool:
    return False          # recognised as a dict-comprehension rebinding, not a test


# G_c: guard class -> predicate over a branch statement's test
GUARD_MATCHERS = {
    "ownership": _g_ownership,
    "role": _g_role,
    "authn": _g_authn,
    "url_validation": _g_url_validation,
    "field_allowlist": _g_field_allowlist,
}


def _test_matches(ctx, fq, s, taint) -> bool:
    return GUARD_MATCHERS[ctx.spec.missing_guard_class](ctx, fq, s, taint)


def _guard_call(ctx, s, depth, down) -> bool:
    """A statement-level call that denies unless its check passes."""
    if s.kind != "expr" or not s.calls:
        return False
    c = next((c for c in s.calls if c.leaf != "__getitem__"), None)
    if c is None:
        return False
    if has_anchor({c.callee_name}, ctx.guard_calls()):
        return True
    return bool(down and depth > 0 and c.callee_fqname
                and _helper_denies(ctx, c.callee_fqname, depth - 1))


def _protected(ctx, fq, u, taint, depth, down=True) -> bool:
    """Is statement `u` of `fq` dominated by a denying guard of the spec's class
    in `fq` itself, or (down arm) by a call to a helper that denies unless its
    guard passes?"""
    g, spec = ctx.g, ctx.spec
    body = g.body(fq)
    if u > 2 and _guard_call(ctx, body.stmt(u), depth, down):
        return True                        # handing the object to the guard is not exposure
    for s in body.real():
        if s.kind in ("if", "assert") and _test_matches(ctx, fq, s, taint) \
                and body.guard_protects(s.id, u):
            return True
        if spec.missing_guard_class == "field_allowlist" and s.dict_filter \
                and body.dominates(s.id, u):
            return True
        if s.id != u and body.dominates(s.id, u) and _guard_call(ctx, s, depth, down):
            return True
    return False


def _helper_denies(ctx, fq, depth) -> bool:
    body = ctx.g.body(fq)
    if not body.reachable(EXIT):
        return False
    return _protected(ctx, fq, EXIT, {}, depth, down=True)


def _decorator_guards(ctx, dec_fq) -> bool:
    """A local decorator whose wrapper runs a denying guard before calling the
    wrapped function."""
    g = ctx.g
    stack = [(dec_fq, set(g.functions[dec_fq].params))]
    while stack:
        fq, outer_params = stack.pop()
        for inner in g.nested_in(fq):
            body = g.body(inner.fqname)
            for s in body.real():
                for c in s.calls:
                    if c.callee_name in outer_params and _protected(ctx, inner.fqname, s.id, {}, 0):
                        return True
            stack.append((inner.fqname, outer_params | set(inner.params)))
    return False


def _up_protected(ctx, fq, depth, seen=None) -> bool:
    g = ctx.g
    seen = seen or set()
    if fq in seen:
        return False
    seen = seen | {fq}
    for d in g.decorators_of(fq):
        if has_anchor({d.decorator}, ctx.decorator_anchors()):
            return True
        if d.decorator_fqname and d.decorator_fqname in g.functions \
                and _decorator_guards(ctx, d.decorator_fqname):
            return True
    if depth <= 0:
        return False
    incoming = g.edges_to(fq)
    if not incoming:
        return False
    for e in incoming:                      # every caller path must be guarded
        body = g.body(e.caller)
        sites = [s.id for s, c in body.calls() if c.callee_fqname == fq]
        ok = sites and all(_protected(ctx, e.caller, sid, {}, ctx.spec.depth) for sid in sites)
        if not (ok or _up_protected(ctx, e.caller, depth - 1, seen)):
            return False
    return True


def has_mitigation(ctx, path: list[Level], taints: list[dict]) -> bool:
    """Alg. 2 with dominance: the exposure is cleared if, at some level of the
    entry -> sink path, every use of the sensitive result is dominated by a
    denying guard (own body; helpers when searching callees), or the entry is
    wrapped by guarding decorators / guarded callers (when searching callers)."""
    spec = ctx.spec
    down = spec.direction in ("callees", "both")
    up = spec.direction in ("callers", "callers_and_self", "both")
    g = ctx.g
    flows_up = True
    for i in range(len(path) - 1, -1, -1):
        lv = path[i]
        body = g.body(lv.fqname)
        if spec.sink_category == "object_read" and lv.bound and flows_up:
            targets = body.uses_of(lv.bound, lv.stmt) or [lv.stmt]
        else:
            targets = [lv.stmt]
        if all(_protected(ctx, lv.fqname, u, taints[i], spec.depth, down=down) for u in targets):
            return True
        if spec.sink_category == "object_read":
            ret = [s for s in body.real() if s.kind == "return"]
            flows_up = bool(lv.bound and any(lv.bound in s.returns_value_reads for s in ret)) \
                or body.stmt(lv.stmt).kind == "return"
    if up and _up_protected(ctx, path[0].fqname, spec.depth):
        return True
    return False


# --- Alg. 1 -----------------------------------------------------------------
def _find_paths(ctx, entry: str):
    g, spec = ctx.g, ctx.spec
    matcher = SINK_MATCHERS[spec.sink_category]
    need_taint = spec.sink_category not in PRIVILEGED_CATEGORIES
    results = []

    def visit(fq, seeds, depth, levels, taints, on_path):
        body = g.body(fq)
        principal = ctx.principal(fq)
        taint = taint_closure(body, seeds, principal, ctx.principal_anchors()) if need_taint else {}
        for h in matcher(g, fq, body, taint, principal, spec):
            lv = Level(fq, h.stmt, h.lineno, h.bound, h.call, tuple(h.tainted))
            results.append((levels + [lv], taints + [taint], h))
        if depth >= spec.depth:
            return
        for s, c in body.calls():
            cf = c.callee_fqname
            if not cf or cf in on_path or cf not in g.functions:
                continue
            if spec.sink_category == "field_write" and c.star_kw:
                continue
            new = _bind(c, g.functions[cf], taint) if need_taint else {}
            if need_taint and not new:
                continue
            lv = Level(fq, s.id, c.lineno, _bound(s), c, tuple(sorted(new)))
            visit(cf, new, depth + 1, levels + [lv], taints + [taint], on_path | {cf})

    visit(entry, _entry_seeds(g, entry) if need_taint else {}, 0, [], [], {entry})
    return results


def _fix_locus(ctx, path, spec) -> str:
    if spec.fix_locus:
        return spec.fix_locus
    if spec.sink_category == "object_read":
        if len(path) == 1:
            return "handler"
        # does the fetched object come back up to the handler?
        for i in range(len(path) - 1, 0, -1):
            body = ctx.g.body(path[i].fqname)
            lv = path[i]
            returned = body.stmt(lv.stmt).kind == "return" or (
                lv.bound and any(lv.bound in s.returns_value_reads
                                 for s in body.real() if s.kind == "return"))
            if not returned:
                return "helper"
        return "handler"
    if spec.sink_category in PRIVILEGED_CATEGORIES and guard_decorators(ctx.g, spec):
        return "decorator"
    return "handler"


def guard_decorators(g, spec) -> list[str]:
    """Local decorators in this codebase that guard the spec's class."""
    ctx = _Ctx(g, spec)
    used = {d.decorator_fqname for d in g.decorator_edges if d.decorator_fqname}
    return sorted(fq for fq in used if fq in g.functions and _decorator_guards(ctx, fq))


def infer_owner_field(graph_or_source, default: str = "user_id") -> str:
    """The key that names a record's owner, inferred per codebase (``user_id``
    here, ``owner_id`` there) from record-shaped dict literals and model
    attributes."""
    pat = re.compile(r"^(user_id|owner_id|owner|account_id|author_id|user)$")
    if isinstance(graph_or_source, str):
        from . import graph as graphmod
        import ast, tempfile, os
        keys = []
        try:
            for n in ast.walk(ast.parse(graph_or_source)):
                if isinstance(n, ast.Dict):
                    ks = [k.value for k in n.keys if isinstance(k, ast.Constant)
                          and isinstance(k.value, str)]
                    if "id" in ks:
                        keys.append(ks)
        except SyntaxError:
            return default
    else:
        keys = graph_or_source.record_dicts()
        # model classes: ``user_id = Column(...)`` / ``owner = ForeignKey(...)``
        for cls in getattr(graph_or_source, "classes", {}).values():
            import ast
            keys.append([t.id for n in cls.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                         for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
                         if isinstance(t, ast.Name)])
    for ks in keys:
        for k in ks:
            if pat.match(k):
                return k
    return default


def detect_with_spec(spec: DetectorSpec, graph) -> list[Finding]:
    if spec.sink_category not in SINK_MATCHERS or spec.missing_guard_class not in GUARD_CLASSES:
        return []
    ctx = _Ctx(graph, spec)
    owner_field = infer_owner_field(graph)
    framework = graph.framework() if hasattr(graph, "framework") else "none"
    out: list[Finding] = []
    seen = set()
    for entry in entries(graph):
        for path, taints, hit in _find_paths(ctx, entry):
            sink = path[-1]
            key = (entry, graph.functions[sink.fqname].file, sink.lineno)
            if key in seen:
                continue
            if has_mitigation(ctx, path, taints):
                continue
            seen.add(key)
            fn = graph.functions[entry]
            top = path[0]
            role = spec.source_role or (pick_role(hit.roles) if hit.roles else "none")
            target = (top.bound if spec.sink_category == "object_read" else None) or (top.tainted[0] if top.tainted else "")
            if spec.sink_category == "field_write" and hit.tainted:
                target = hit.tainted[0] if len(path) == 1 else (top.tainted[0] if top.tainted else "")
            out.append(Finding(
                issue_class=spec.issue_class, func=fn.name,
                sink_lineno=sink.lineno, sink_assign_target=target,
                tainted_args=list(hit.tainted), sink_src=hit.src,
                file_path=fn.file, owner_field=owner_field,
                transform_id=spec.transform_id, source_role=role,
                sink_category=spec.sink_category,
                missing_guard_class=spec.missing_guard_class,
                fix_locus=_fix_locus(ctx, path, spec), fqname=entry,
                sink_file=graph.functions[sink.fqname].file, path=path,
                entry_lineno=top.lineno, framework=framework))
    return out


# --- the built-in catalog: five cells of the same language ---------------------
BUILTIN_SPECS = {
    "BOLA": DetectorSpec("BOLA", sink=SinkMatcher("object_read"),
                         missing_guard="ownership", search=BOTH,
                         fix_template="insert_ownership_guard"),
    "BFLA": DetectorSpec("BFLA", sink=SinkMatcher("privileged_mutation"),
                         missing_guard="role", search=BOTH,
                         fix_template="insert_role_guard_at_start"),
    "MASS_ASSIGNMENT": DetectorSpec("MASS_ASSIGNMENT", sink=SinkMatcher("field_write"),
                                    missing_guard="field_allowlist", search=BOTH,
                                    fix_template="insert_field_allowlist"),
    "SSRF": DetectorSpec("SSRF", sink=SinkMatcher("outbound_fetch"),
                         missing_guard="url_validation", search=BOTH,
                         fix_template="insert_url_validation_before_sink"),
    "MISSING_AUTH": DetectorSpec("MISSING_AUTH", sink=SinkMatcher("sensitive_action"),
                                 missing_guard="authn", search=BOTH,
                                 fix_template="insert_authn_guard_at_start"),
}


def detect_bola(graph):
    return detect_with_spec(BUILTIN_SPECS["BOLA"], graph)


def detect_bfla(graph):
    return detect_with_spec(BUILTIN_SPECS["BFLA"], graph)


def detect_mass_assignment(graph):
    return detect_with_spec(BUILTIN_SPECS["MASS_ASSIGNMENT"], graph)


def detect_ssrf(graph):
    return detect_with_spec(BUILTIN_SPECS["SSRF"], graph)


def detect_missing_auth(graph):
    return detect_with_spec(BUILTIN_SPECS["MISSING_AUTH"], graph)


DETECTORS = {
    "BOLA": detect_bola, "BFLA": detect_bfla,
    "MASS_ASSIGNMENT": detect_mass_assignment,
    "SSRF": detect_ssrf, "MISSING_AUTH": detect_missing_auth,
}
ALL_CLASSES = list(DETECTORS.keys())


def detect_all(graph) -> list[Finding]:
    out: list[Finding] = []
    for cls in ALL_CLASSES:
        out += DETECTORS[cls](graph)
    return out


def detect_registered(graph, specs):
    """Run admitted catalog specs — adding a class is data, not engine code."""
    out: list[Finding] = []
    for spec in specs:
        out += detect_with_spec(spec, graph)
    return out


def detect_prioritized(graph, priority: list[str]):
    """Run detectors in `priority` order. NON-GATING: the order is always
    completed to a full permutation of ALL_CLASSES, so recall equals the full
    sweep and triage only changes cost-to-first (1-based position of first hit)."""
    order = [c for c in priority if c in DETECTORS]
    order += [c for c in ALL_CLASSES if c not in order]
    findings: list[Finding] = []
    cost_to_first = None
    for i, cls in enumerate(order):
        fs = DETECTORS[cls](graph)
        if fs and cost_to_first is None:
            cost_to_first = i + 1
        findings += fs
    return findings, cost_to_first
