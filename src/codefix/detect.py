"""Structural, name-independent BOLA detection (slice: Tier 0 + a slice of Tier 1).

The point this slice proves: detection keys on *shapes and resolved principal
symbols*, NOT on helper names. A mitigation is recognised as a comparison
involving a principal source (`current_user_id` / `current_user` / ...),
regardless of whether it sits in a helper named `assert_owns`, `gate`, or
nothing at all. Rename the guard helper and detection is unaffected.

Finding shape (BOLA): a *root* function (entry point) whose parameter flows
into a data-access call, with no principal-comparison guard on its callee
path. That absence is the cross-function signal a file-local linter can't see.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .graph import CodeGraph
from .taint import tainted_values

# Resolved principal sources (stand-in for framework auth symbols like
# flask_login.current_user). NOT application helper names — those are renameable.
PRINCIPAL_ANCHORS = {
    "current_user_id", "current_user", "get_current_user",
    "user", "request_user",
}

# Owner-field patterns: the key on the fetched object that names its owner.
# Inferred per-codebase so the SAME template re-renders correctly (user_id here,
# owner_id there) — this is what makes a recipe transfer rather than a frozen diff.
OWNER_FIELD_PATTERN = re.compile(r"^(user_id|owner_id|owner|account_id)$")


def infer_owner_field(source: str, default: str = "user_id") -> str:
    """Find the object's owner-field name by scanning *object-like* dict literals.

    An object-like dict has an 'id' key (it's a record), distinguishing it from
    an auth-context holder like {"uid": ...}. Among those, pick the key naming
    the owner. This is why the same template renders user_id for shop and
    owner_id for library — the field is inferred, not hardcoded.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return default
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys = [k.value for k in node.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            if "id" not in keys:
                continue  # not an object/record dict
            for k in keys:
                if OWNER_FIELD_PATTERN.match(k):
                    return k
    return default


# Role anchors for BFLA: a privileged-operation gate compares against one of
# these (resolved/role-attribute style), regardless of the guard's own name.
ROLE_ANCHORS = {"role", "is_admin", "admin", "is_staff", "permissions"}
# Privileged-operation signal: a state-changing call (name-independent shape).
MUTATION_METHODS = {"pop", "remove", "delete", "drop", "clear"}


@dataclass
class Finding:
    issue_class: str
    func: str
    sink_lineno: int              # insert point (after sink, or first body stmt)
    sink_assign_target: str       # variable the sink result is bound to (BOLA)
    tainted_args: list[str]
    sink_src: str
    file_path: str
    owner_field: str = "user_id"  # inferred per-codebase (BOLA)
    transform_id: str = "insert_ownership_guard"
    # facets (stamped by a DetectorSpec; empty => fingerprint uses class fallback)
    source_role: str = ""
    sink_category: str = ""
    missing_guard_class: str = ""
    fix_locus: str = ""


def _name_of(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _refs_param(node: ast.expr, params: set[str]) -> list[str]:
    out: list[str] = []
    for c in ast.walk(node):
        if isinstance(c, ast.Name) and c.id in params and c.id not in out:
            out.append(c.id)
    return out


def _contains_principal(node: ast.AST) -> bool:
    """True if the subtree references a principal source (call / name / attr)."""
    for c in ast.walk(node):
        if isinstance(c, ast.Call):
            if _name_of(c) in PRINCIPAL_ANCHORS:
                return True
        if isinstance(c, ast.Attribute) and c.attr in PRINCIPAL_ANCHORS:
            return True
        if isinstance(c, ast.Name) and c.id in PRINCIPAL_ANCHORS:
            return True
    return False


def _branch_denies(if_node: ast.If) -> bool:
    """The if-body (or else) denies access: raises or returns early."""
    for stmt in if_node.body + if_node.orelse:
        for n in ast.walk(stmt):
            if isinstance(n, (ast.Raise, ast.Return)):
                return True
    return False


def _is_dominating_guard(fn_node: ast.AST, predicate) -> bool:
    """M3 dominance: a denial-guard `if <predicate>: raise/return` that DOMINATES
    the body — a top-level statement of the function (executes on every path),
    not one nested inside another conditional that may be skipped. `predicate`
    matches the guard's test, so each defect class supplies its own guard shape."""
    for stmt in getattr(fn_node, "body", []):
        if isinstance(stmt, ast.If) and predicate(stmt.test) and _branch_denies(stmt):
            return True
    return False


def _has_dominating_guard(graph: CodeGraph, func: str, predicate) -> bool:
    """A denial-guard whose test matches `predicate` and DOMINATES the sink:
    top-level in the function, OR in a helper called at top level
    (interprocedural), OR a wrapping decorator. Name-independent (shape, not
    helper name); branch-sensitive. Generic over the guard predicate so BOLA
    (principal), SSRF (url validation), and missing-auth (authn) all reuse it."""
    fn0 = graph.functions.get(func)
    if fn0 is None:
        return False
    if _is_dominating_guard(fn0.node, predicate):
        return True
    for stmt in fn0.node.body:                      # interprocedural: top-level helper
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call):
                hfn = graph.functions.get(_name_of(n))
                if hfn is not None and _is_dominating_guard(hfn.node, predicate):
                    return True
    for dname in fn0.decorators:                    # up the chain: decorator
        dfn = graph.functions.get(dname)
        if dfn is not None and any(
                isinstance(n, ast.If) and predicate(n.test) and _branch_denies(n)
                for n in ast.walk(dfn.node)):
            return True
    return False


def _has_principal_guard(graph: CodeGraph, func: str) -> bool:
    return _has_dominating_guard(graph, func, _contains_principal)


# --- anchors for the remaining classes (resolved library/role symbols) -------
FETCH_ANCHORS = {"fetch_url", "urlopen", "urlretrieve", "http_fetch", "fetch_remote"}
SENSITIVE_ACTIONS = {"transfer", "send_money", "charge", "place_order", "wire", "payout"}
AUTHN_ANCHORS = {"current_user", "current_user_id", "get_current_user",
                 "token_validator", "require_auth"}


def _contains_authn(node: ast.AST) -> bool:
    for c in ast.walk(node):
        if isinstance(c, ast.Call) and _name_of(c) in AUTHN_ANCHORS:
            return True
        if isinstance(c, ast.Attribute) and c.attr in AUTHN_ANCHORS:
            return True
        if isinstance(c, ast.Name) and c.id in AUTHN_ANCHORS:
            return True
    return False


def _tainted_sink(fn_node: ast.FunctionDef, params: set[str]):
    """Find the first `target = call(... tainted ...)` assignment, where 'tainted'
    is computed by def-use propagation (M3) — so taint threaded through
    intermediate assignments/attributes/calls is caught, not just direct params."""
    taint = tainted_values(fn_node, params)
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            # a `**kwargs` call is mass-assignment; a fetch/sensitive call is
            # SSRF/missing-auth — none of those are BOLA data-reads
            if any(kw.arg is None for kw in n.value.keywords):
                continue
            if _name_of(n.value) in FETCH_ANCHORS or _name_of(n.value) in SENSITIVE_ACTIONS:
                continue
            flowing = sorted({c.id for c in ast.walk(n.value)
                              if isinstance(c, ast.Name) and c.id in taint})
            if flowing and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                # don't report the taint-defining assignment itself as the sink
                if n.targets[0].id in params:
                    continue
                return n.targets[0].id, n.lineno, flowing, ast.unparse(n)
    return None


def detect_bola(graph: CodeGraph) -> list[Finding]:
    findings: list[Finding] = []
    owner_field = infer_owner_field(graph.source)
    for func in graph.roots():
        fn = graph.functions[func]
        params = set(fn.params)
        if not params:
            continue
        sink = _tainted_sink(fn.node, params)
        if sink is None:
            continue
        if _has_principal_guard(graph, func):
            continue  # mitigated — ownership/principal comparison on the path
        target, lineno, tainted, src = sink
        findings.append(Finding(
            issue_class="BOLA",
            func=func,
            sink_lineno=lineno,
            sink_assign_target=target,
            tainted_args=tainted,
            sink_src=src,
            file_path=graph.file_path,
            owner_field=owner_field,
            transform_id="insert_ownership_guard",
        ))
    return findings


# --- BFLA: privileged operation reachable with no role gate on the path ------

def _contains_role(node: ast.AST) -> bool:
    for c in ast.walk(node):
        if isinstance(c, ast.Attribute) and c.attr in ROLE_ANCHORS:
            return True
        if isinstance(c, ast.Name) and c.id in ROLE_ANCHORS:
            return True
        if isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value in ROLE_ANCHORS:
            return True  # e.g. obj["role"]
    return False


# Framework role/auth decorators we can't see the body of (resolved-symbol style).
ROLE_DECORATOR_ANCHORS = {
    "admin_required", "login_required", "requires_admin", "requires_role",
    "roles_required", "permission_required",
}


def _has_role_gate(graph: CodeGraph, func: str) -> bool:
    """Dominance-aware: a role comparison that is guaranteed to run before the
    privileged op — searched DOWN the chain (callees) AND UP the chain
    (decorators that wrap this entry point). A guard anywhere on a dominating
    path counts, regardless of its name."""
    # down the chain: this function + its callees
    scope = {func} | graph.callees(func, depth=2)
    for name in scope:
        fn = graph.functions.get(name)
        if fn is None:
            continue
        for n in ast.walk(fn.node):
            if isinstance(n, ast.Compare) and _contains_role(n):
                return True
    # up the chain: decorators wrapping this entry point dominate the body
    fn0 = graph.functions[func]
    for dname in fn0.decorators:
        if dname in ROLE_DECORATOR_ANCHORS:
            return True                       # known framework guard decorator
        dfn = graph.functions.get(dname)      # local decorator — scan its body
        if dfn is not None:
            for n in ast.walk(dfn.node):
                if isinstance(n, ast.Compare) and _contains_role(n):
                    return True
    return False


def _reaches_mutation(graph: CodeGraph, func: str) -> bool:
    """Name-independent privileged-op signal: a state-changing call (.pop/.remove
    /...) or a `del` anywhere on the callee path."""
    scope = {func} | graph.callees(func, depth=2)
    for name in scope:
        fn = graph.functions.get(name)
        if fn is None:
            continue
        for n in ast.walk(fn.node):
            if isinstance(n, ast.Delete):
                return True
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr in MUTATION_METHODS:
                return True
    return False


def detect_bfla(graph: CodeGraph) -> list[Finding]:
    findings: list[Finding] = []
    for func in graph.roots():
        fn = graph.functions[func]
        if not _reaches_mutation(graph, func):
            continue
        if _has_role_gate(graph, func):
            continue  # role/permission comparison on the path
        body_lineno = fn.node.body[0].lineno if fn.node.body else fn.lineno + 1
        findings.append(Finding(
            issue_class="BFLA",
            func=func,
            sink_lineno=body_lineno,
            sink_assign_target="",
            tainted_args=[],
            sink_src=f"privileged op reachable from {func}",
            file_path=graph.file_path,
            transform_id="insert_role_guard_at_start",
        ))
    return findings


# --- Mass assignment: user dict -> model via **kwargs, no field allowlist -----

def _has_allowlist(fn_node: ast.AST, dictvar: str) -> bool:
    """The tainted dict is reconstructed via a dict-comprehension (allowlist)
    before use — name-independent: we look for the filter shape, not a helper."""
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.DictComp) \
                and any(isinstance(t, ast.Name) and t.id == dictvar for t in n.targets):
            return True
    return False


def detect_mass_assignment(graph: CodeGraph) -> list[Finding]:
    out: list[Finding] = []
    for func in graph.roots():
        fn = graph.functions[func]
        params = set(fn.params)
        if not params:
            continue
        taint = tainted_values(fn.node, params)
        for n in ast.walk(fn.node):
            if not (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)):
                continue
            # sink: Call with `**<tainted dict>`
            star = next((kw for kw in n.value.keywords
                         if kw.arg is None and isinstance(kw.value, ast.Name)
                         and kw.value.id in taint), None)
            if star is None or not (len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)):
                continue
            dictvar = star.value.id
            if _has_allowlist(fn.node, dictvar):
                continue
            out.append(Finding(
                issue_class="MASS_ASSIGNMENT", func=func, sink_lineno=n.lineno,
                sink_assign_target=dictvar, tainted_args=[dictvar],
                sink_src=ast.unparse(n), file_path=graph.file_path,
                transform_id="insert_field_allowlist",
                source_role="request_body", sink_category="model_write",
                missing_guard_class="field_allowlist", fix_locus="sink_local"))
            break
    return out


# --- SSRF: tainted URL -> fetch sink, no URL-validation guard on the path -----

def detect_ssrf(graph: CodeGraph) -> list[Finding]:
    out: list[Finding] = []
    for func in graph.roots():
        fn = graph.functions[func]
        params = set(fn.params)
        if not params:
            continue
        taint = tainted_values(fn.node, params)
        sink = None
        for n in ast.walk(fn.node):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) \
                    and _name_of(n.value) in FETCH_ANCHORS:
                targs = sorted({c.id for c in ast.walk(n.value)
                                if isinstance(c, ast.Name) and c.id in taint})
                if targs and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    sink = (n.lineno, targs)
                    break
        if sink is None:
            continue
        # mitigation: a dominating denial-guard that examines the tainted URL
        pred = lambda test, t=taint: any(isinstance(c, ast.Name) and c.id in t
                                         for c in ast.walk(test))
        if _has_dominating_guard(graph, func, pred):
            continue
        lineno, targs = sink
        out.append(Finding(
            issue_class="SSRF", func=func, sink_lineno=lineno,
            sink_assign_target=targs[0], tainted_args=targs,
            sink_src=f"fetch of user-controlled {targs[0]}", file_path=graph.file_path,
            transform_id="insert_url_validation_before_sink",
            source_role="param", sink_category="url_fetch",
            missing_guard_class="url_validation", fix_locus="sink_local"))
    return out


# --- Missing auth: sensitive action reachable with no authn step on the path --

def detect_missing_auth(graph: CodeGraph) -> list[Finding]:
    out: list[Finding] = []
    for func in graph.roots():
        fn = graph.functions[func]
        scope = {func} | graph.callees(func, depth=2)
        reaches = any(
            isinstance(n, ast.Call) and _name_of(n) in SENSITIVE_ACTIONS
            for name in scope if graph.functions.get(name)
            for n in ast.walk(graph.functions[name].node))
        if not reaches:
            continue
        if _has_dominating_guard(graph, func, _contains_authn):
            continue                          # an authn check dominates -> authenticated
        body_lineno = fn.node.body[0].lineno if fn.node.body else fn.lineno + 1
        out.append(Finding(
            issue_class="MISSING_AUTH", func=func, sink_lineno=body_lineno,
            sink_assign_target="", tainted_args=[],
            sink_src=f"sensitive action reachable from {func} with no authn",
            file_path=graph.file_path, transform_id="insert_authn_guard_at_start",
            source_role="param", sink_category="sensitive_op",
            missing_guard_class="authn", fix_locus="entry_local"))
    return out


# registry: issue_class -> detector. ALL_CLASSES is the full deterministic sweep.
DETECTORS = {
    "BOLA": detect_bola, "BFLA": detect_bfla,
    "MASS_ASSIGNMENT": detect_mass_assignment,
    "SSRF": detect_ssrf, "MISSING_AUTH": detect_missing_auth,
}
ALL_CLASSES = list(DETECTORS.keys())


def detect_all(graph: CodeGraph) -> list[Finding]:
    out: list[Finding] = []
    for cls in ALL_CLASSES:
        out += DETECTORS[cls](graph)
    return out


def detect_registered(graph: CodeGraph, specs):
    """Run developer-authored (admitted) DetectorSpecs (M13). The engine
    interprets them as data — adding a class is a persisted spec, not new code."""
    out: list[Finding] = []
    for spec in specs:
        out += detect_with_spec(spec, graph)
    return out


def detect_prioritized(graph: CodeGraph, priority: list[str]):
    """Run detectors in `priority` order. NON-GATING by construction: `priority`
    must be a permutation of ALL_CLASSES, so every detector still runs and recall
    is identical to the full sweep — triage only changes ORDER (cost-to-first).
    Returns (findings, cost_to_first) where cost = 1-based position of first hit."""
    order = [c for c in priority if c in DETECTORS]
    order += [c for c in ALL_CLASSES if c not in order]   # guarantee completeness
    findings: list[Finding] = []
    cost_to_first = None
    for i, cls in enumerate(order):
        fs = DETECTORS[cls](graph)
        if fs and cost_to_first is None:
            cost_to_first = i + 1
        findings += fs
    return findings, cost_to_first


# --- Declarative spec-driven detection (the developer-extensible path) -------

@dataclass
class DetectorSpec:
    """A new issue type as data — added via the authoring gate, no engine code."""
    issue_class: str
    flow: str                 # "param_to_sink" | "privileged_op"
    transform_id: str
    source_role: str
    sink_category: str
    missing_guard_class: str
    fix_locus: str


def detect_with_spec(spec: DetectorSpec, graph: CodeGraph) -> list[Finding]:
    """Run a declarative spec. Reuses the same name-independent flow primitives
    as the built-in detectors, stamping the spec's issue_class + facets."""
    out: list[Finding] = []
    if spec.flow == "param_to_sink":
        owner_field = infer_owner_field(graph.source)
        for func in graph.roots():
            fn = graph.functions[func]
            params = set(fn.params)
            if not params:
                continue
            sink = _tainted_sink(fn.node, params)
            if sink is None or _has_principal_guard(graph, func):
                continue
            target, lineno, tainted, src = sink
            out.append(Finding(
                issue_class=spec.issue_class, func=func, sink_lineno=lineno,
                sink_assign_target=target, tainted_args=tainted, sink_src=src,
                file_path=graph.file_path, owner_field=owner_field,
                transform_id=spec.transform_id, source_role=spec.source_role,
                sink_category=spec.sink_category,
                missing_guard_class=spec.missing_guard_class, fix_locus=spec.fix_locus))
    elif spec.flow == "privileged_op":
        for func in graph.roots():
            fn = graph.functions[func]
            if not _reaches_mutation(graph, func) or _has_role_gate(graph, func):
                continue
            body_lineno = fn.node.body[0].lineno if fn.node.body else fn.lineno + 1
            out.append(Finding(
                issue_class=spec.issue_class, func=func, sink_lineno=body_lineno,
                sink_assign_target="", tainted_args=[],
                sink_src=f"privileged op reachable from {func}",
                file_path=graph.file_path, transform_id=spec.transform_id,
                source_role=spec.source_role, sink_category=spec.sink_category,
                missing_guard_class=spec.missing_guard_class, fix_locus=spec.fix_locus))
    return out
