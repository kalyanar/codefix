"""CodeMap — the live, cross-file call graph of one codebase (paper §III.B).

Build is three-pass (ported from codefix v1's CodeMap and extended):

  1. collect every FunctionDef / AsyncFunctionDef, including class methods and
     nested functions, as `FunctionNode`s keyed by fully-qualified name;
  2. build a per-module ``local name -> fqname`` map for imports, resolving
     relative imports against the current package;
  3. walk each function body's Call nodes and best-effort-resolve the callee
     against imports, module-local functions, and sibling methods. Unresolved
     external calls (``requests.get``) keep ``callee_fqname=None`` but the edge
     is still recorded with the raw name and its import-qualified symbol.

The builder also records intra-procedural def-use edges and decorator edges.
Per-function statement IR + CFG (`FunctionBody`) is derived lazily from the
AST handle. CodeMap is never persisted — it is rebuilt on every scan.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from .ir import CallSite, FunctionBody, Stmt, ENTRY, EXIT, RAISE

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "env", "node_modules",
             "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist"}
# a request-aborting call ends the path like a raise (flask/werkzeug abort)
ABORT_LEAVES = {"abort"}
# reproducers and tests live next to the code but are not the code under scan
HARNESS_GLOBS = ("exploit*.py", "legit*.py", "bypass*.py", "contract*.py", "adversarial*.py",
                 "run_*.py", "test_*.py", "*_test.py", "tests.py", "conftest.py")


def harness_excluder(rel: Path) -> bool:
    import fnmatch
    if any(p in ("tests", "test", ".codefix", "migrations") for p in rel.parts[:-1]):
        return True
    return any(fnmatch.fnmatch(rel.name, pat) for pat in HARNESS_GLOBS)


@dataclass
class FunctionNode:
    fqname: str
    name: str
    module: str
    qualname: str
    parent_class: str | None
    file: str
    lineno: int
    end_lineno: int
    params: list[str]
    decorators: list[str]              # as written, dotted; call-decorators reduced to callee
    node: ast.AST = field(repr=False, default=None)   # AST handle
    enclosing: str | None = None       # fqname of the enclosing function (nested defs)

    @property
    def file_path(self) -> str:
        return self.file

    @property
    def is_method(self) -> bool:
        return self.parent_class is not None


@dataclass
class CallEdge:
    caller: str
    callee_name: str
    callee_fqname: str | None
    lineno: int
    callee_symbol: str | None = None

    @property
    def caller_fqname(self) -> str:
        return self.caller

    @property
    def leaf(self) -> str:
        return self.callee_name.rsplit(".", 1)[-1]

    @property
    def resolved(self) -> bool:
        return self.callee_fqname is not None


@dataclass
class DefUseEdge:
    func: str
    target: str        # name bound
    source: str        # name read by the defining expression
    lineno: int


@dataclass
class DecoratorEdge:
    func: str
    decorator: str
    decorator_fqname: str | None
    lineno: int
    args: list = field(default_factory=list)   # literal args of a call-decorator (route paths)


class CodeGraph:
    """The CodeMap. Satisfies `callgraph.CallGraphProvider`."""

    language = "python"

    def __init__(self, root: str):
        self.root = root
        self.functions: dict[str, FunctionNode] = {}
        self.edges: list[CallEdge] = []
        self.defuse: list[DefUseEdge] = []
        self.decorator_edges: list[DecoratorEdge] = []
        self.imports: dict[str, dict[str, str]] = {}     # module -> local -> fq target
        self.modules: dict[str, str] = {}                # module -> file
        self.sources: dict[str, str] = {}                # file -> text
        self.trees: dict[str, ast.Module] = {}
        self.classes: dict[str, ast.ClassDef] = {}       # fq class -> node
        self._out: dict[str, list[CallEdge]] = {}
        self._in: dict[str, list[CallEdge]] = {}
        self._bodies: dict[str, FunctionBody] = {}
        self.build_seconds = 0.0

    # --- compat with the single-file slice API ---------------------------
    @property
    def file_path(self) -> str:
        return next(iter(self.sources), self.root)

    @property
    def source(self) -> str:
        return "\n".join(self.sources.values())

    @property
    def calls(self) -> dict[str, set[str]]:
        return {fq: {e.callee_fqname for e in self._out.get(fq, []) if e.callee_fqname}
                for fq in self.functions}

    # --- queries ---------------------------------------------------------
    def resolve_name(self, name: str) -> str | None:
        """fqname for a fqname or an unambiguous short name / qualname."""
        if name in self.functions:
            return name
        hits = [fq for fq, f in self.functions.items() if f.name == name or f.qualname == name]
        return hits[0] if len(hits) == 1 else (hits[0] if hits else None)

    def get(self, name: str) -> FunctionNode | None:
        fq = self.resolve_name(name)
        return self.functions.get(fq) if fq else None

    def edges_from(self, name: str) -> list[CallEdge]:
        fq = self.resolve_name(name)
        return list(self._out.get(fq, [])) if fq else []

    def edges_to(self, name: str) -> list[CallEdge]:
        fq = self.resolve_name(name)
        return list(self._in.get(fq, [])) if fq else []

    def callers_of(self, name: str) -> set[str]:
        return {e.caller for e in self.edges_to(name)}

    def callees_of(self, name: str) -> set[str]:
        return {e.callee_fqname for e in self.edges_from(name) if e.callee_fqname}

    def decorators_of(self, name: str) -> list[DecoratorEdge]:
        fq = self.resolve_name(name)
        return [d for d in self.decorator_edges if d.func == fq]

    def roots(self) -> list[str]:
        """Entry points: top-level functions/methods with no resolved caller."""
        return [fq for fq, f in self.functions.items()
                if f.enclosing is None and not self._in.get(fq)]

    def callees(self, name: str, depth: int = 2) -> set[str]:
        fq = self.resolve_name(name)
        seen: set[str] = set()
        frontier = {fq} if fq else set()
        for _ in range(depth):
            nxt: set[str] = set()
            for f in frontier:
                for c in self.callees_of(f):
                    if c not in seen:
                        seen.add(c)
                        nxt.add(c)
            frontier = nxt
        return seen

    def body(self, name: str) -> FunctionBody:
        fq = self.resolve_name(name)
        if fq not in self._bodies:
            fn = self.functions[fq]
            self._bodies[fq] = _BodyBuilder(self, fn).build()
        return self._bodies[fq]

    def nested_in(self, fq: str) -> list[FunctionNode]:
        return [f for f in self.functions.values() if f.enclosing == fq]

    def record_dicts(self) -> list[list[str]]:
        """Key lists of record-shaped dict literals (have an ``id`` key)."""
        out = []
        for tree in self.trees.values():
            for n in ast.walk(tree):
                if isinstance(n, ast.Dict):
                    keys = [k.value for k in n.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                    if "id" in keys:
                        out.append(keys)
        return out

    def module_constants(self) -> dict[str, tuple[str, ast.AST]]:
        """Module-level ``NAME = <literal>`` bindings: name -> (module, value node)."""
        out = {}
        for mod, file in self.modules.items():
            for n in self.trees[file].body:
                if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                        and isinstance(n.targets[0], ast.Name):
                    out.setdefault(n.targets[0].id, (mod, n.value))
        return out

    def framework(self) -> str:
        roots = set()
        for imp in self.imports.values():
            roots |= {t.split(".")[0] for t in imp.values()}
        for fw in ("fastapi", "flask", "django", "rest_framework"):
            if fw in roots:
                return "django" if fw == "rest_framework" else fw
        return "none"


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def _iter_py_files(root: Path, exclude) -> list[Path]:
    if root.is_file():
        return [root]
    out = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts[:-1]):
            continue
        if exclude and exclude(rel):
            continue
        out.append(p)
    return out


def _module_name(root: Path, p: Path) -> str:
    if root.is_file():
        return p.stem
    parts = list(p.relative_to(root).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or p.stem


def build(path: str, exclude=None) -> CodeGraph:
    """Build the CodeMap for a file or a directory tree."""
    import time
    t0 = time.perf_counter()
    root = Path(path).resolve()
    g = CodeGraph(str(root))
    parsed = []
    for p in _iter_py_files(root, exclude):
        try:
            text = p.read_text()
            tree = ast.parse(text)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue
        mod = _module_name(root, p)
        g.sources[str(p)] = text
        g.trees[str(p)] = tree
        g.modules[mod] = str(p)
        parsed.append((mod, str(p), tree))

    # pass 1: functions (+ methods, nested) and classes
    for mod, file, tree in parsed:
        _collect_functions(g, mod, file, tree)
    # pass 2: imports
    for mod, file, tree in parsed:
        g.imports[mod] = _collect_imports(mod, tree, is_pkg=Path(file).name == "__init__.py")
    # pass 3: call edges, def-use edges, decorator edges
    for fn in list(g.functions.values()):
        _record(g, fn)
    for e in g.edges:
        g._out.setdefault(e.caller, []).append(e)
        if e.callee_fqname:
            g._in.setdefault(e.callee_fqname, []).append(e)
    g.build_seconds = time.perf_counter() - t0
    return g


def _dotted(expr: ast.AST) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        head = _dotted(expr.value)
        return f"{head}.{expr.attr}" if head else None
    if isinstance(expr, ast.Call):
        return _dotted(expr.func)
    return None


def _decorator_name(d: ast.expr) -> str:
    if isinstance(d, ast.Call):
        d = d.func
    return _dotted(d) or "<expr>"


def _params(node) -> list[str]:
    a = node.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names


def _collect_functions(g: CodeGraph, mod: str, file: str, tree: ast.Module):
    def visit(body, cls: str | None, enclosing: str | None, prefix: str):
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{stmt.name}"
                fq = f"{mod}.{qual}" if mod else qual
                params = _params(stmt)
                if cls and params and params[0] in ("self", "cls"):
                    params = params[1:]
                g.functions[fq] = FunctionNode(
                    fqname=fq, name=stmt.name, module=mod, qualname=qual,
                    parent_class=cls, file=file, lineno=stmt.lineno,
                    end_lineno=stmt.end_lineno or stmt.lineno, params=params,
                    decorators=[_decorator_name(d) for d in stmt.decorator_list],
                    node=stmt, enclosing=enclosing)
                visit(stmt.body, None, fq, f"{qual}.")
            elif isinstance(stmt, ast.ClassDef):
                g.classes[f"{mod}.{prefix}{stmt.name}"] = stmt
                visit(stmt.body, stmt.name, enclosing, f"{prefix}{stmt.name}.")
            elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                for sub in ("body", "orelse", "finalbody", "handlers"):
                    child = getattr(stmt, sub, None) or []
                    if sub == "handlers":
                        for h in child:
                            visit(h.body, cls, enclosing, prefix)
                    else:
                        visit(child, cls, enclosing, prefix)
    visit(tree.body, None, None, "")


def _collect_imports(mod: str, tree: ast.Module, is_pkg: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    pkg = mod.split(".") if is_pkg else mod.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    out[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level - 1 > len(pkg):
                    continue
                base = pkg[: len(pkg) - (node.level - 1)]
                if node.module:
                    base = base + node.module.split(".")
                base_s = ".".join(base)
            else:
                base_s = node.module or ""
            for a in node.names:
                if a.name == "*":
                    continue
                out[a.asname or a.name] = f"{base_s}.{a.name}" if base_s else a.name
    return out


def _resolve(g: CodeGraph, fn: FunctionNode, called: str) -> tuple[str | None, str | None]:
    """-> (callee_fqname if defined in this graph, import-qualified symbol)."""
    imports = g.imports.get(fn.module, {})
    head, _, tail = called.partition(".")

    def local(fq):
        if fq in g.functions:
            return fq
        if f"{fq}.__init__" in g.functions:     # class construction
            return f"{fq}.__init__"
        return None

    if head in ("self", "cls") and fn.parent_class and tail and "." not in tail:
        owner = fn.qualname.rsplit(".", 1)[0]
        fq = local(f"{fn.module}.{owner}.{tail}")
        return fq, fq
    if head in imports:
        sym = imports[head] + (f".{tail}" if tail else "")
        return local(sym), sym
    if not tail:
        # nested function defined in an enclosing scope, then module level
        scope = fn.fqname
        while scope:
            fq = local(f"{scope}.{head}")
            if fq:
                return fq, fq
            scope = g.functions[scope].enclosing if scope in g.functions else None
        fq = local(f"{fn.module}.{head}")
        return fq, (fq or None)
    fq = local(f"{fn.module}.{called}")               # Class.method in same module
    return fq, fq


def _own_nodes(fn_node):
    """AST nodes of a function body, not descending into nested defs/lambdas/classes."""
    stack = list(fn_node.body)
    while stack:
        n = stack.pop()
        yield n
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            stack.append(c)


def _record(g: CodeGraph, fn: FunctionNode):
    for n in _own_nodes(fn.node):
        if isinstance(n, ast.Call):
            name = _dotted(n.func)
            if name:
                fq, sym = _resolve(g, fn, name)
                g.edges.append(CallEdge(fn.fqname, name, fq, n.lineno, sym))
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n.value is not None:
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            reads = {c.id for c in ast.walk(n.value) if isinstance(c, ast.Name)}
            for t in targets:
                for tn in ast.walk(t):
                    if isinstance(tn, ast.Name):
                        for r in sorted(reads):
                            g.defuse.append(DefUseEdge(fn.fqname, tn.id, r, n.lineno))
    for d in fn.node.decorator_list:
        name = _decorator_name(d)
        fq, _ = _resolve(g, fn, name) if name != "<expr>" else (None, None)
        args = [a.value for a in getattr(d, "args", []) if isinstance(a, ast.Constant)]
        g.decorator_edges.append(DecoratorEdge(fn.fqname, name, fq, d.lineno, args))


# ---------------------------------------------------------------------------
# statement IR + CFG for one function
# ---------------------------------------------------------------------------

_OPS = {ast.Eq: "eq", ast.NotEq: "ne", ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt",
        ast.GtE: "ge", ast.Is: "is", ast.IsNot: "isnot", ast.In: "in", ast.NotIn: "notin"}


def _test_ops(expr) -> frozenset:
    return frozenset(_OPS[type(op)] for n in ast.walk(expr) if isinstance(n, ast.Compare)
                     for op in n.ops if type(op) in _OPS)


def _expr_facts(g: CodeGraph, fn: FunctionNode, expr: ast.AST | None):
    """-> (reads, tokens, calls, has_compare_or_call) for an expression."""
    reads, tokens, calls = set(), set(), []
    compare = False
    if expr is None:
        return reads, tokens, calls, compare
    stack = [expr]
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            reads.add(n.id)
            tokens.add(n.id)
        elif isinstance(n, ast.Attribute):
            tokens.add(n.attr)
            d = _dotted(n)
            if d:
                tokens.add(d)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            tokens.add(n.value)
        elif isinstance(n, ast.Compare):
            compare = True
        elif isinstance(n, ast.Call):
            compare = True
            name = _dotted(n.func)
            if name:
                tokens.add(name.rsplit(".", 1)[-1])
                tokens.add(name)
                fq, sym = _resolve(g, fn, name)
                recv = name.rsplit(".", 1)[0] if "." in name else ""
                cs = CallSite(name, fq, sym, n.lineno, recv)
                for a in n.args:
                    r, t, _, _ = _expr_facts(g, fn, a)
                    cs.arg_reads.append(frozenset(r))
                    cs.arg_tokens.append(frozenset(t))
                star = set()
                for kw in n.keywords:
                    r, t, _, _ = _expr_facts(g, fn, kw.value)
                    if kw.arg is None:
                        star |= r
                    else:
                        cs.kw_reads[kw.arg] = frozenset(r)
                        cs.kw_tokens[kw.arg] = frozenset(t)
                cs.star_kw = frozenset(star)
                # receiver reads count as reads of the call
                calls.append(cs)
        elif isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load):
            base = _dotted(n.value)
            if base:
                r, t, _, _ = _expr_facts(g, fn, n.slice)
                cs = CallSite(f"{base}.__getitem__", None, None, n.lineno, base,
                              [frozenset(r)], [frozenset(t)])
                calls.append(cs)
        stack.extend(ast.iter_child_nodes(n))
    return reads, tokens, calls, compare


class _BodyBuilder:
    def __init__(self, g: CodeGraph, fn: FunctionNode):
        self.g, self.fn = g, fn
        self.stmts: list[Stmt] = [Stmt(ENTRY, "entry"), Stmt(EXIT, "exit"), Stmt(RAISE, "raise")]
        self.succ: dict[int, set[int]] = {ENTRY: set(), EXIT: set(), RAISE: set()}
        self.loops: list[tuple[int, list[int]]] = []   # (header, break-sources)
        self.handlers: list[list[int]] = []            # raise targets inside try

    def build(self) -> FunctionBody:
        ft = self.seq(self.fn.node.body, {ENTRY}, None, None)
        for s in ft:
            self.edge(s, EXIT)
        body = FunctionBody(self.stmts, self.succ)
        _finalize_heads(body)
        return body

    def edge(self, a, b):
        self.succ.setdefault(a, set()).add(b)

    def new(self, node, kind, parent, region, expr=None, test=None) -> Stmt:
        sid = len(self.stmts)
        s = Stmt(sid, kind, getattr(node, "lineno", 0), getattr(node, "end_lineno", 0),
                 parent=parent, region=region, node=node)
        if expr is not None:
            reads, tokens, calls, _ = _expr_facts(self.g, self.fn, expr)
            s.reads, s.tokens, s.calls = frozenset(reads), frozenset(tokens), calls
        if test is not None:
            reads, tokens, calls, cmp_ = _expr_facts(self.g, self.fn, test)
            s.test_reads, s.test_tokens, s.test_calls, s.test_compares = \
                frozenset(reads), frozenset(tokens), calls, cmp_
            s.test_ops = _test_ops(test)
        self.stmts.append(s)
        self.succ[sid] = set()
        return s

    def raise_target(self):
        return self.handlers[-1] if self.handlers else [RAISE]

    def seq(self, body, preds: set[int], parent, region) -> set[int]:
        cur = set(preds)
        for node in body:
            if not cur:            # unreachable code after return/raise
                cur = set()
            cur = self.one(node, cur, parent, region)
        return cur

    def link(self, preds, sid):
        for p in preds:
            self.edge(p, sid)

    def one(self, node, preds, parent, region) -> set[int]:
        if isinstance(node, ast.If):
            s = self.new(node, "if", parent, region, test=node.test)
            self.link(preds, s.id)
            n_before = len(self.stmts)
            body_ft = self.seq(node.body, {s.id}, s.id, "body")
            body_head = n_before if len(self.stmts) > n_before else None
            n_before = len(self.stmts)
            if node.orelse:
                else_ft = self.seq(node.orelse, {s.id}, s.id, "orelse")
                else_head = n_before if len(self.stmts) > n_before else None
                heads = tuple(h for h in (body_head, else_head) if h is not None)
                s.branch_heads = heads
                return body_ft | else_ft
            s.branch_heads = ("__fallthrough__",) if body_head is None else (body_head, "__fallthrough__")
            return body_ft | {s.id}
        if isinstance(node, ast.Assert):
            s = self.new(node, "assert", parent, region, test=node.test)
            self.link(preds, s.id)
            for t in self.raise_target():
                self.edge(s.id, t)
            s.branch_heads = ("__fallthrough__", RAISE)
            return {s.id}
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            test = node.test if isinstance(node, ast.While) else node.iter
            s = self.new(node, "loop", parent, region, test=test)
            if not isinstance(node, ast.While):
                r, t, c, _ = _expr_facts(self.g, self.fn, node.target)
                s.writes = frozenset(x.id for x in ast.walk(node.target) if isinstance(x, ast.Name))
                s.reads = frozenset(s.test_reads)
            self.link(preds, s.id)
            self.loops.append((s.id, []))
            body_ft = self.seq(node.body, {s.id}, s.id, "body")
            for b in body_ft:
                self.edge(b, s.id)
            _, breaks = self.loops.pop()
            infinite = isinstance(node, ast.While) and isinstance(node.test, ast.Constant) \
                and bool(node.test.value)
            after = set() if infinite else {s.id}
            if node.orelse:
                after = self.seq(node.orelse, after, s.id, "orelse")
            return after | set(breaks)
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            s = self.new(node, "try", parent, region)
            self.link(preds, s.id)
            handler_heads: list[int] = []
            # reserve handler entry statements so raises inside the body can target them
            hstmts = [self.new(h, "handler", s.id, "handlers") for h in node.handlers]
            handler_heads = [h.id for h in hstmts]
            self.handlers.append(handler_heads or self.raise_target())
            body_ft = self.seq(node.body, {s.id}, s.id, "body")
            self.handlers.pop()
            for h in handler_heads:            # any body point may raise into a handler
                self.edge(s.id, h)
            out = set()
            if node.orelse:
                body_ft = self.seq(node.orelse, body_ft, s.id, "orelse")
            out |= body_ft
            for hs, h in zip(hstmts, node.handlers):
                out |= self.seq(h.body, {hs.id}, s.id, "handlers")
            if node.finalbody:
                out = self.seq(node.finalbody, out, s.id, "finalbody")
            return out
        if isinstance(node, (ast.With, ast.AsyncWith)):
            s = self.new(node, "with", parent, region,
                         expr=ast.Tuple([i.context_expr for i in node.items], ast.Load()))
            s.writes = frozenset(x.id for i in node.items if i.optional_vars is not None
                                 for x in ast.walk(i.optional_vars) if isinstance(x, ast.Name))
            self.link(preds, s.id)
            return self.seq(node.body, {s.id}, s.id, "body")
        if isinstance(node, ast.Match):
            s = self.new(node, "if", parent, region, test=node.subject)
            self.link(preds, s.id)
            out = {s.id}
            heads = []
            for case in node.cases:
                n_before = len(self.stmts)
                out |= self.seq(case.body, {s.id}, s.id, "case")
                if len(self.stmts) > n_before:
                    heads.append(n_before)
            s.branch_heads = tuple(heads) + ("__fallthrough__",)
            return out
        return self.simple(node, preds, parent, region)

    def simple(self, node, preds, parent, region) -> set[int]:
        kind = "other"
        expr = None
        if isinstance(node, ast.Return):
            kind, expr = "return", node.value
        elif isinstance(node, ast.Raise):
            kind, expr = "raise", node.exc
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            kind, expr = "assign", node.value
        elif isinstance(node, ast.Expr):
            kind, expr = "expr", node.value
        elif isinstance(node, ast.Delete):
            kind, expr = "delete", ast.Tuple(node.targets, ast.Load())
        s = self.new(node, kind, parent, region, expr=expr)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            w, bases = set(), set()
            for t in targets:
                if isinstance(t, (ast.Name, ast.Tuple, ast.List)):
                    w |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
                elif isinstance(t, (ast.Attribute, ast.Subscript)):
                    base = t.value
                    while isinstance(base, (ast.Attribute, ast.Subscript)):
                        base = base.value
                    if isinstance(base, ast.Name):
                        bases.add(base.id)
                    r, tk, c, _ = _expr_facts(self.g, self.fn,
                                              t.slice if isinstance(t, ast.Subscript) else None)
                    s.reads = s.reads | frozenset(r)
            if isinstance(node, ast.AugAssign):
                s.reads = s.reads | frozenset(w)
            s.writes, s.store_bases = frozenset(w), frozenset(bases)
            s.dict_filter = isinstance(node.value, ast.DictComp)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            s.writes = frozenset({node.name})
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            s.writes = frozenset(a.asname or a.name.split(".")[0] for a in node.names)
        if kind == "return":
            s.returns_value_reads = s.reads
        self.link(preds, s.id)
        if kind == "return":
            self.edge(s.id, EXIT)
            return set()
        aborts = any(c.leaf in ABORT_LEAVES for c in s.calls) and kind == "expr"
        if kind == "raise" or aborts:
            s.denies = True
            for t in self.raise_target():
                self.edge(s.id, t)
            return set()
        if isinstance(node, ast.Break) and self.loops:
            self.loops[-1][1].append(s.id)
            return set()
        if isinstance(node, ast.Continue) and self.loops:
            self.edge(s.id, self.loops[-1][0])
            return set()
        if self.handlers and s.calls:
            for t in self.handlers[-1]:
                if t != RAISE:
                    self.edge(s.id, t)
        return {s.id}


def _finalize_heads(body: FunctionBody):
    """Replace the ``__fallthrough__`` placeholder with the actual successor(s) of
    a branch statement that are not one of its explicit branch heads."""
    for s in body.stmts:
        if "__fallthrough__" in s.branch_heads:
            explicit = [h for h in s.branch_heads if h != "__fallthrough__"]
            rest = sorted(body.succ.get(s.id, set()) - set(explicit))
            s.branch_heads = tuple(explicit + rest)

