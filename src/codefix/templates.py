"""Templates and producers (paper §III.F): `TemplateSpec` + `render_patch`.

A `TemplateSpec` names a transform from a small registry — insert a dominating
ownership / role / authentication guard, a URL-validation check before an
outbound fetch, or a field allow-list before a write (one per defect class) —
plus parameters: the guard helper (``assert_owns``), the user reference
(``current_user_id()``), the denial statement and any import it needs.

Rendering fills every parameter from the *target's own AST* (ported from codefix
v1's helper discovery and extended): the owner field and its access style
(``rec["owner_id"]`` vs ``book.owner_id``), the principal accessor the codebase
already uses, an existing guard helper / guard decorator / URL validator /
allow-list constant when there is one, and the framework's denial idiom. So one
template applies unchanged across codebases, and the rendered diff is exactly
the change the validator applies and the pull request shows.
"""
from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TemplateSpec:
    name: str
    issue_class: str
    transform_id: str
    params: dict = field(default_factory=dict)     # explicit overrides


BUILTIN_TEMPLATES = [
    TemplateSpec("bola_ownership_guard", "BOLA", "insert_ownership_guard"),
    TemplateSpec("bfla_role_guard", "BFLA", "insert_role_guard_at_start"),
    TemplateSpec("missing_auth_guard", "MISSING_AUTH", "insert_authn_guard_at_start"),
    TemplateSpec("ssrf_validate_guard", "SSRF", "insert_url_validation_before_sink"),
    TemplateSpec("mass_assignment_allowlist", "MASS_ASSIGNMENT", "insert_field_allowlist"),
]


@dataclass
class RenderedPatch:
    transform_id: str
    root: str
    files: dict                      # relpath -> (before, after)
    diff: str
    guard: str                       # the inserted check, one line
    params: dict

    def write_to(self, dst_root: str):
        for rel, (_, after) in self.files.items():
            Path(dst_root, rel).write_text(after)


class RenderError(Exception):
    pass


# --- parameter discovery over the target AST ---------------------------------
DENY = {
    "flask": ("abort({code})", "from flask import abort"),
    "django": ("raise PermissionDenied", "from django.core.exceptions import PermissionDenied"),
    "fastapi": ('raise HTTPException(status_code={code}, detail="{msg}")',
                "from fastapi import HTTPException"),
    "none": ('raise PermissionError("{msg}")', None),
}
PRINCIPAL_ID_FUNCS = ("current_user_id", "get_current_user_id", "current_uid")
PRINCIPAL_USER_FUNCS = ("current_user", "get_current_user", "get_current_active_user")


def _module_of(graph, file):
    for mod, f in graph.modules.items():
        if f == file:
            return mod
    return None


def _module_names(graph, file) -> set[str]:
    """Names usable at module scope of `file`: its functions and its imports."""
    mod = _module_of(graph, file)
    names = {fn.name for fn in graph.functions.values()
             if fn.module == mod and fn.enclosing is None and fn.parent_class is None}
    names |= set(graph.imports.get(mod, {}))
    return names


def _importable(graph, module: str) -> str:
    """The name a module is imported by. CodeMap names modules from the scan root, so a src
    layout yields `src.pkg.mod`; `src/` is a source root, not a package, so drop it."""
    root = Path(graph.root)
    if module.startswith("src.") and (root / "src").is_dir() and not (root / "src" / "__init__.py").exists():
        return module[len("src."):]
    return module


def _imported_symbol(graph, file, local):
    return graph.imports.get(_module_of(graph, file), {}).get(local)


def _record_style(graph) -> str:
    return "subscript" if graph.record_dicts() else "attribute"


def _access(obj, fieldname, style):
    return f'{obj}["{fieldname}"]' if style == "subscript" else f"{obj}.{fieldname}"


def _dict_values_for_key(graph, key):
    vals = []
    for tree in graph.trees.values():
        for n in ast.walk(tree):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and k.value == key \
                            and isinstance(v, ast.Constant) and isinstance(v.value, str):
                        vals.append(v.value)
    return vals


def _entry_has_param(graph, finding, name):
    fn = graph.functions.get(finding.fqname)
    return fn is not None and name in _all_params(fn)


def _all_params(fn):
    a = fn.node.args
    return [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]


def discover(graph, finding, overrides=None) -> dict:
    """Fill a template's parameters from the target codebase."""
    from .detect import BUILTIN_SPECS, _Ctx, _helper_denies, guard_decorators, DetectorSpec
    p: dict = {}
    file = finding.file_path
    names = _module_names(graph, file)
    fw = graph.framework()
    p["framework"] = fw
    deny, imp = DENY.get(fw, DENY["none"])
    p["deny"], p["deny_import"] = deny, imp
    if imp and imp.rsplit(" ", 1)[-1] in names:
        p["deny_import"] = None
    # principal references
    flask_login = _imported_symbol(graph, file, "current_user") in ("flask_login.current_user",)
    id_func = next((f for f in PRINCIPAL_ID_FUNCS if f in names), None)
    user_func = next((f for f in PRINCIPAL_USER_FUNCS if f in names), None)
    p["principal_imports"] = []
    # the accessor may live in another module of the codebase: import it
    for want, pool in (("id", PRINCIPAL_ID_FUNCS), ("user", PRINCIPAL_USER_FUNCS)):
        if (id_func if want == "id" else user_func):
            continue
        for fn in graph.functions.values():
            if fn.name in pool and fn.enclosing is None and fn.parent_class is None \
                    and fn.module != _module_of(graph, file):
                p["principal_imports"].append(f"from {_importable(graph, fn.module)} import {fn.name}")
                if want == "id":
                    id_func = fn.name
                else:
                    user_func = fn.name
                break
    if flask_login:
        p["user_id_ref"], p["user_ref"] = "current_user.id", "current_user"
        p["authn_test"] = "not current_user.is_authenticated"
    elif _entry_has_param(graph, finding, "request") and fw == "django":
        p["user_id_ref"], p["user_ref"] = "request.user.id", "request.user"
        p["authn_test"] = "not request.user.is_authenticated"
    else:
        p["user_id_ref"] = f"{id_func}()" if id_func else (f"{user_func}()" if user_func else None)
        p["user_ref"] = f"{user_func}()" if user_func else (f"{id_func}()" if id_func else None)
        p["authn_test"] = f"{p['user_ref']} is None" if p["user_ref"] else None
    p["style"] = _record_style(graph)
    p["owner_field"] = finding.owner_field
    p["scopes"] = principal_scopes(graph)
    # role field + privileged value, read off the user records
    roles = _dict_values_for_key(graph, "role")
    p["role_field"] = "role" if roles else ("is_admin" if "is_admin" in graph.source else "role")
    p["admin_value"] = next((v for v in roles if "admin" in v), roles[0] if roles else "admin")
    # an existing ownership guard helper (a function that denies unless the
    # principal owns its argument) — name-independent, found by shape
    bola = _Ctx(graph, BUILTIN_SPECS["BOLA"])
    p["guard_helper"] = None
    for fq, fn in graph.functions.items():
        if fq == finding.fqname or fn.enclosing or not fn.params or fn.name not in names:
            continue
        try:
            if _helper_denies(bola, fq, 1):
                p["guard_helper"] = fn.name
                break
        except KeyError:
            continue
    # an existing guard decorator for role / authn classes
    cls = {"insert_role_guard_at_start": "role",
           "insert_authn_guard_at_start": "authn"}.get(finding.transform_id)
    p["guard_decorator"] = None
    if cls:
        spec = DetectorSpec("X", sink_category="privileged_mutation", missing_guard_class=cls,
                            transform_id=finding.transform_id)
        for fq in guard_decorators(graph, spec):
            if graph.functions[fq].name in names:
                p["guard_decorator"] = graph.functions[fq].name
                break
    # URL validator helper: one param, returns a comparison over it, fetches nothing
    p["url_validator"] = None
    for fq, fn in graph.functions.items():
        if fn.enclosing or len(fn.params) != 1 or fn.name not in names or fq == finding.fqname:
            continue
        if any(lv.fqname == fq for lv in finding.path):
            continue
        body = graph.body(fq)
        rets = [s for s in body.real() if s.kind == "return"]
        fetches = any(c.callee_symbol and c.callee_symbol.startswith(("urllib", "requests", "httpx"))
                      for _, c in body.calls())
        param = fn.params[0]
        if rets and not fetches and all(isinstance(s.node.value, (ast.Compare, ast.BoolOp))
                                        for s in rets) \
                and any(param in s.reads or s.reads & {w for t in body.real() for w in t.writes}
                        for s in rets):
            p["url_validator"] = fn.name
            break
    # allow-list constant
    p["allowlist"] = None
    for name, (mod, val) in graph.module_constants().items():
        if re.search(r"ALLOW|WHITELIST|PERMITTED|FIELDS", name) \
                and isinstance(val, (ast.Set, ast.List, ast.Tuple)) \
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in val.elts) \
                and name in _module_level_names(graph, file) and "HOST" not in name:
            p["allowlist"] = name
            break
    p["allowed_hosts"] = next((n for n in _module_level_names(graph, file)
                               if re.search(r"ALLOWED_HOSTS|HOST_ALLOWLIST", n)), None)
    p.update(overrides or {})
    return p


def principal_scopes(graph) -> list[dict]:
    """How this codebase already ties an object to the authenticated principal:
    ``User.query.filter_by(username=resp['sub'])`` says the User model's
    ``username`` field holds the principal expression ``resp['sub']``."""
    from .taint import PRINCIPAL_ANCHORS, has_anchor
    out = []
    for fq, fn in graph.functions.items():
        body = graph.body(fq)
        for s, c in body.calls():
            base = c.receiver.split(".")[0] if c.receiver else ""
            if base not in {k.rsplit(".", 1)[-1] for k in graph.classes}:
                continue
            for kw, toks in c.kw_tokens.items():
                if not has_anchor(toks, PRINCIPAL_ANCHORS) and not _reads_principal_var(graph, fq, c, kw):
                    continue
                expr = _kw_source(graph, fn, s, c, kw)
                if expr:
                    out.append({"model": base, "field": kw, "expr": expr, "func": fq})
    return out


def _reads_principal_var(graph, fq, c, kw):
    from .taint import principal_closure
    reads = c.kw_reads.get(kw, frozenset())
    if not reads:
        return False
    return bool(reads & principal_closure(graph.body(fq)))


def _kw_source(graph, fn, s, c, kw):
    src = graph.sources[fn.file]
    for n in ast.walk(s.node):
        if isinstance(n, ast.Call) and n.lineno == c.lineno:
            for k in n.keywords:
                if k.arg == kw:
                    return ast.get_source_segment(src, k.value)
    return None


def _relationship_attr(graph, model: str, target: str) -> str | None:
    """``user = relationship("User")`` / ``user = models.ForeignKey(User)`` on `model`."""
    for fq, cls in graph.classes.items():
        if fq.rsplit(".", 1)[-1] != model:
            continue
        for n in cls.body:
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) \
                    and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                leaf = (ast.unparse(n.value.func)).rsplit(".", 1)[-1]
                args = [ast.unparse(a).strip("'\"") for a in n.value.args]
                if leaf in ("relationship", "ForeignKey", "OneToOneField") and target in args:
                    return n.targets[0].id
    return None


def _scoped_test(graph, finding, obj, p):
    """An ownership test in the codebase's own scoping idiom, if it has one and the
    principal expression is available where the guard goes."""
    sink_call = finding.path[-1].call
    if sink_call is None or not sink_call.receiver:
        return None
    model = sink_call.receiver.split(".")[0]
    entry = graph.functions[finding.path[0].fqname if finding.fix_locus != "helper"
                            else finding.path[-1].fqname]
    bound_here = {w for s in graph.body(entry.fqname).real() for w in s.writes} | set(entry.params)
    for sc in p["scopes"]:
        base = re.match(r"[A-Za-z_]\w*", sc["expr"])
        if not base or (base.group(0) not in bound_here and base.group(0) not in
                        _module_names(graph, entry.file)):
            continue
        if sc["model"] == model:
            return f"{obj}.{sc['field']} != {sc['expr']}"
        rel = _relationship_attr(graph, model, sc["model"])
        if rel:
            return f"{obj}.{rel}.{sc['field']} != {sc['expr']}"
    return None


def guard_idioms(graph, finding) -> list[dict]:
    """Ownership guards the codebase already writes (``if user != order.user:
    return Response(..., 403)`` under ``@jwt_auth_required``): the test, the object
    it protects, the denial it uses and the decorators that supply the principal.
    Same class first, then same module, then anywhere."""
    from .detect import AUTH_DECORATOR_RX, BUILTIN_SPECS, _Ctx, _g_ownership, _principal_at
    ctx = _Ctx(graph, BUILTIN_SPECS["BOLA"])
    entry = graph.functions[finding.fqname]
    out = []
    for fq, fn in graph.functions.items():
        if fq == finding.fqname:
            continue
        body = graph.body(fq)
        for s in body.real():
            node = s.node
            if s.kind != "if" or node.orelse or not node.body:
                continue
            last = node.body[-1]
            if not isinstance(last, (ast.Return, ast.Raise)):
                continue
            if not _g_ownership(ctx, fq, s, {}):
                continue
            principal = _principal_at(ctx, fq, s) & s.test_reads
            called = {c.callee_name.split(".")[0] for c in s.test_calls if c.leaf != "__getitem__"}
            objs = s.test_reads - principal - called
            if len(objs) != 1 or not principal:
                continue
            decos = [d for d in fn.node.decorator_list
                     if AUTH_DECORATOR_RX.search(ast.unparse(d))]
            rank = 0 if fn.parent_class and fn.parent_class == entry.parent_class and \
                fn.module == entry.module else (1 if fn.module == entry.module else 2)
            out.append({"rank": rank, "fq": fq, "file": fn.file, "test": node.test,
                        "obj": next(iter(objs)), "principal": principal, "deny": node.body,
                        "decorators": decos, "module": fn.module})
    return sorted(out, key=lambda d: d["rank"])


class _Rename(ast.NodeTransformer):
    def __init__(self, old, new):
        self.old, self.new = old, new

    def visit_Name(self, n):
        if n.id == self.old:
            return ast.copy_location(ast.Name(self.new, n.ctx), n)
        return n


def _source_block(graph, file, stmts, indent):
    lines = graph.sources[file].splitlines()
    first, last = stmts[0], stmts[-1]
    block = lines[first.lineno - 1:last.end_lineno]
    cut = first.col_offset
    return [indent + (ln[cut:] if ln[:cut].strip() == "" else ln.lstrip()) for ln in block]


def _module_level_names(graph, file):
    tree = graph.trees[file]
    out = set()
    for n in tree.body:
        if isinstance(n, ast.Assign):
            out |= {t.id for t in n.targets if isinstance(t, ast.Name)}
    return out


# --- edits ----------------------------------------------------------------
def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _deny_stmt(p, code, msg):
    return p["deny"].format(code=code, msg=msg)


def _first_body_line(fn_node) -> int:
    body = fn_node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None),
                                                             ast.Constant) \
            and isinstance(body[0].value.value, str) and len(body) > 1:
        return body[1].lineno
    return body[0].lineno


def _t_ownership(graph, f, p, lines):
    idx = len(f.path) - 1 if f.fix_locus == "helper" else 0
    lv = f.path[idx]
    body = graph.body(lv.fqname)
    s = body.stmt(lv.stmt)
    file = graph.functions[lv.fqname].file
    src = lines[file]
    ind = _indent(src[s.lineno - 1])
    if lv.bound:
        obj, edits, after = lv.bound, [], s.end_lineno
    elif s.kind == "return" and s.node.value is not None:
        obj = "obj"
        expr = ast.get_source_segment(graph.sources[file], s.node.value)
        edits = [("replace", s.lineno, s.end_lineno, [f"{ind}{obj} = {expr}"])]
        after = None
    else:
        raise RenderError("sink result is not bound; cannot place an ownership guard")
    scoped = _scoped_test(graph, f, obj, p)
    entry = graph.functions[lv.fqname]
    entry_names = set(entry.params) | {w for st in body.real() for w in st.writes}
    idiom = None
    for cand in guard_idioms(graph, f):
        needs = cand["principal"]
        deco_src = {ast.unparse(d) for d in cand["decorators"]}
        have = {ast.unparse(d) for d in entry.node.decorator_list}
        if needs <= entry_names or (needs <= set(entry.params) and deco_src):
            idiom = cand
            break
    if idiom and not p.get("guard_helper"):
        test = ast.unparse(_Rename(idiom["obj"], obj).visit(
            ast.parse(ast.unparse(idiom["test"]), mode="eval")).body)
        guard = [f"{ind}if {test}:"] + _source_block(graph, idiom["file"], idiom["deny"], ind + "    ")
        text = f"if {test}: " + " ".join(ln.strip() for ln in guard[1:])
        imports = []
        missing = [d for d in idiom["decorators"] if ast.unparse(d) not in
                   {ast.unparse(x) for x in entry.node.decorator_list}]
        if missing:
            def_ind = _indent(src[entry.node.lineno - 1])
            edits.append(("insert_before", entry.node.lineno, entry.node.lineno,
                          [f"{def_ind}@{ast.unparse(d)}" for d in missing]))
            text = " ".join(f"@{ast.unparse(d)}" for d in missing) + " + " + text
            names = _module_names(graph, file)
            for d in missing:
                head = ast.unparse(d).split("(")[0].split(".")[0]
                if head not in names:
                    sym = graph.imports.get(idiom["module"], {}).get(head)
                    if sym:
                        imports.append(f"from {_importable(graph, sym.rsplit('.', 1)[0])} import {head}")
        if after is not None:
            edits.append(("insert_after", after, after, guard))
        else:
            edits.append(("insert_after", s.end_lineno, s.end_lineno, guard + [f"{ind}return {obj}"]))
        return file, edits, text, imports
    if p.get("guard_helper"):
        guard = [f"{ind}{p['guard_helper']}({obj})"]
        text = guard[0].strip()
    else:
        if scoped:
            test = f"{obj} is not None and {scoped}"
        elif not p.get("user_id_ref"):
            raise RenderError("no principal accessor found in this codebase")
        else:
            test = f"{obj} is not None and {_access(obj, p['owner_field'], p['style'])} != {p['user_id_ref']}"
        guard = [f"{ind}if {test}:", f"{ind}    {_deny_stmt(p, 403, 'not owner')}"]
        text = f"if {test}: {_deny_stmt(p, 403, 'not owner')}"
    if after is not None:
        edits.append(("insert_after", after, after, guard))
    else:
        edits.append(("insert_after", s.end_lineno, s.end_lineno, guard + [f"{ind}return {obj}"]))
    imports = [] if p.get("guard_helper") else [p.get("deny_import")] + \
        ([] if scoped else p["principal_imports"])
    return file, edits, text, imports


def _t_entry_guard(graph, f, p, lines, test, code, msg, decorator):
    fn = graph.functions[f.fqname]
    src = lines[fn.file]
    if decorator:
        ind = _indent(src[fn.node.lineno - 1])
        return fn.file, [("insert_before", fn.node.lineno, fn.node.lineno,
                          [f"{ind}@{decorator}"])], f"@{decorator}", []
    if not test:
        raise RenderError("no principal accessor found in this codebase")
    at = _first_body_line(fn.node)
    ind = _indent(src[at - 1])
    deny = _deny_stmt(p, code, msg)
    return fn.file, [("insert_before", at, at, [f"{ind}if {test}:", f"{ind}    {deny}"])], \
        f"if {test}: {deny}", [p.get("deny_import")] + p["principal_imports"]


def _t_role(graph, f, p, lines):
    user = p.get("user_ref")
    test = None
    if user:
        if p["style"] == "subscript" and not user.startswith(("current_user.", "request.")) \
                and user != "current_user":
            test = f'{user} is None or {user}.get("{p["role_field"]}") != "{p["admin_value"]}"'
        else:
            test = f'{user} is None or getattr({user}, "{p["role_field"]}", None) != "{p["admin_value"]}"'
    deco = p.get("guard_decorator") if f.fix_locus == "decorator" else None
    return _t_entry_guard(graph, f, p, lines, test, 403, "forbidden", deco)


def _t_authn(graph, f, p, lines):
    deco = p.get("guard_decorator") if f.fix_locus == "decorator" else None
    return _t_entry_guard(graph, f, p, lines, p.get("authn_test"), 401,
                          "authentication required", deco)


def _t_url_validation(graph, f, p, lines):
    lv = f.path[0]
    body = graph.body(lv.fqname)
    s = body.stmt(lv.stmt)
    file = graph.functions[lv.fqname].file
    ind = _indent(lines[file][s.lineno - 1])
    url = lv.tainted[0] if lv.tainted else f.sink_assign_target
    deny = _deny_stmt(p, 403, "blocked url")
    imports = [p.get("deny_import")]
    if p.get("url_validator"):
        test = f"not {p['url_validator']}({url})"
    elif p.get("allowed_hosts"):
        test = f"urllib.parse.urlsplit({url}).hostname not in {p['allowed_hosts']}"
        imports.append("import urllib.parse")
    else:
        test = (f"not urllib.parse.urlsplit({url}).hostname or "
                f"ipaddress.ip_address(socket.gethostbyname(urllib.parse.urlsplit({url}).hostname))"
                f".is_private")
        imports += ["import ipaddress", "import socket", "import urllib.parse"]
    return file, [("insert_before", s.lineno, s.lineno, [f"{ind}if {test}:", f"{ind}    {deny}"])], \
        f"if {test}: {deny}", imports


def _t_allowlist(graph, f, p, lines):
    lv = f.path[0]
    body = graph.body(lv.fqname)
    s = body.stmt(lv.stmt)
    file = graph.functions[lv.fqname].file
    ind = _indent(lines[file][s.lineno - 1])
    dv = f.sink_assign_target
    if p.get("allowlist"):
        new = f"{dv} = {{k: {dv}[k] for k in {p['allowlist']} if k in {dv}}}"
    else:
        new = (f"{dv} = {{k: v for k, v in {dv}.items() if k not in "
               f"{{'is_admin', 'role', 'is_staff', 'is_superuser', 'permissions'}}}}")
    return file, [("insert_before", s.lineno, s.lineno, [f"{ind}{new}"])], new, []


TRANSFORMS = {
    "insert_ownership_guard": _t_ownership,
    "insert_role_guard_at_start": _t_role,
    "insert_authn_guard_at_start": _t_authn,
    "insert_url_validation_before_sink": _t_url_validation,
    "insert_field_allowlist": _t_allowlist,
}


def _add_imports(text: str, imports: list[str]) -> str:
    if not imports:
        return text
    tree = ast.parse(text)
    have = {ast.get_source_segment(text, n).strip() for n in tree.body
            if isinstance(n, (ast.Import, ast.ImportFrom))}
    todo = [i for i in imports if i not in have]
    if not todo:
        return text
    lines = text.splitlines(keepends=True)
    at = 0
    for n in tree.body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            at = n.end_lineno
        elif at == 0 and isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, str):
            at = n.end_lineno
        elif not isinstance(n, (ast.Import, ast.ImportFrom)):
            break
    block = [i + "\n" for i in todo]
    return "".join(lines[:at] + block + lines[at:])


def render_patch(spec: TemplateSpec | str, finding, graph, overrides=None) -> RenderedPatch:
    """Materialize a template into a concrete multi-file edit for this codebase."""
    tid = spec if isinstance(spec, str) else spec.transform_id
    fn = TRANSFORMS.get(tid)
    if fn is None:
        raise RenderError(f"no transform {tid!r}")
    params = discover(graph, finding, overrides or
                      (spec.params if isinstance(spec, TemplateSpec) else None))
    lines = {path: text.splitlines() for path, text in graph.sources.items()}
    out = fn(graph, finding, params, lines)
    file, edits, guard, imports = out
    imports = [i for i in imports if i]
    before = graph.sources[file]
    src = before.splitlines()
    for kind, start, end, new in sorted(edits, key=lambda e: e[1], reverse=True):
        if kind == "replace":
            src[start - 1:end] = new
        elif kind == "insert_after":
            src[end:end] = new
        else:
            src[start - 1:start - 1] = new
    after = "\n".join(src) + ("\n" if before.endswith("\n") else "")
    after = _add_imports(after, imports)
    ast.parse(after)                       # the rendered fix must still be valid Python
    root = graph.root if Path(graph.root).is_dir() else str(Path(graph.root).parent)
    rel = str(Path(file).relative_to(root))
    diff = "".join(difflib.unified_diff(before.splitlines(keepends=True),
                                        after.splitlines(keepends=True),
                                        f"a/{rel}", f"b/{rel}"))
    return RenderedPatch(tid, root, {rel: (before, after)}, diff, guard, params)
