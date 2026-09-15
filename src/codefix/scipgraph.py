"""A SCIP-derived CallGraphProvider (paper §III.E: "CodeMap is one provider;
SCIP-derived graphs from scip-python / scip-typescript are another").

The index supplies what a language front end is hardest to get right —
definitions, references and cross-file symbol resolution. Statement structure
for brace languages (TypeScript / JavaScript / Java / Go-style bodies) is read
from the source text inside each function's enclosing range: branches, loops,
returns, throws, declarations, assignments and call sites. From those the
provider emits the same statement IR and control-flow graph as the Python
CodeMap, so the unchanged engine (taint, dominance, bounded search, facets)
runs over it. Fix rendering stays Python-only: on these codebases codefix
detects and fingerprints.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .graph import CallEdge, FunctionNode
from .ir import CallSite, FunctionBody, Stmt, ENTRY, EXIT, RAISE
from .scip import ROLE_DEFINITION, ROLE_IMPORT, ROLE_WRITE, parse_symbol, read_index

IDENT = r"[A-Za-z_$][\w$]*"
CHAIN_RX = re.compile(rf"{IDENT}(?:\s*\.\s*{IDENT})*")
STRING_RX = re.compile(r"'([^'\\]*)'|\"([^\"\\]*)\"|`([^`\\]*)`")
KEYWORDS = {"if", "else", "for", "while", "do", "return", "throw", "const", "let", "var",
            "new", "try", "catch", "finally", "switch", "case", "break", "continue",
            "function", "await", "async", "typeof", "instanceof", "in", "of", "true",
            "false", "null", "undefined", "this", "void"}


# --- lexical helpers --------------------------------------------------------------
def _skip_string(text, i):
    q = text[i]
    i += 1
    while i < len(text) and text[i] != q:
        i += 2 if text[i] == "\\" else 1
    return i + 1


def _skip_ws(text, i, end):
    while i < end:
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = end if j < 0 else j + 1
        elif text.startswith("/*", i):
            j = text.find("*/", i)
            i = end if j < 0 else j + 2
        else:
            break
    return i


def _match(text, i, end):
    """Index just past the bracket closing the one at `i`."""
    pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
    open_c, close_c = text[i], pairs[text[i]]
    depth = 0
    while i < end:
        c = text[i]
        if c in "'\"`":
            i = _skip_string(text, i)
            continue
        if text.startswith("//", i) or text.startswith("/*", i):
            i = _skip_ws(text, i, end)
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return end


def _stmt_end(text, i, end):
    """End of a simple statement: `;` at depth 0, or a newline at depth 0 that
    does not continue the expression."""
    depth = 0
    while i < end:
        c = text[i]
        if c in "'\"`":
            i = _skip_string(text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif c == ";" and depth == 0:
            return i + 1
        elif c == "\n" and depth == 0:
            prev = text[:i].rstrip()[-1:] if text[:i].rstrip() else ""
            nxt = text[_skip_ws(text, i, end):_skip_ws(text, i, end) + 1]
            if prev not in "=+-*/%&|,(?:<>!." and nxt not in ".?+-*/%&|=<>)":
                return i
        i += 1
    return end


@dataclass
class _Node:
    kind: str                       # if loop return throw decl assign expr block try
    start: int
    end: int
    cond: tuple | None = None       # (start, end) of the condition / iterated expression
    then: list = field(default_factory=list)
    orelse: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    finally_: list = field(default_factory=list)


def _word_at(text, i):
    m = re.match(IDENT, text[i:i + 40])
    return m.group(0) if m else ""


def _parse_block(text, i, end) -> list[_Node]:
    out = []
    while True:
        i = _skip_ws(text, i, end)
        if i >= end:
            return out
        node, i = _parse_stmt(text, i, end)
        if node is not None:
            out.append(node)


def _parse_body(text, i, end):
    """A braced block or a single statement -> (nodes, next index)."""
    i = _skip_ws(text, i, end)
    if i < end and text[i] == "{":
        close = _match(text, i, end)
        return _parse_block(text, i + 1, close - 1), close
    node, j = _parse_stmt(text, i, end)
    return ([node] if node else []), j


def _parse_stmt(text, i, end):
    w = _word_at(text, i)
    if text[i] == "{":
        close = _match(text, i, end)
        return _Node("block", i, close, then=_parse_block(text, i + 1, close - 1)), close
    if text[i] == ";":
        return None, i + 1
    if w == "if":
        p = _skip_ws(text, i + 2, end)
        close = _match(text, p, end)
        then, j = _parse_body(text, close, end)
        node = _Node("if", i, j, cond=(p + 1, close - 1), then=then)
        k = _skip_ws(text, j, end)
        if _word_at(text, k) == "else":
            node.orelse, j = _parse_body(text, k + 4, end)
            node.end = j
        return node, j
    if w in ("for", "while"):
        p = _skip_ws(text, i + len(w), end)
        close = _match(text, p, end)
        body, j = _parse_body(text, close, end)
        return _Node("loop", i, j, cond=(p + 1, close - 1), then=body), j
    if w == "try":
        body, j = _parse_body(text, i + 3, end)
        node = _Node("try", i, j, then=body)
        k = _skip_ws(text, j, end)
        if _word_at(text, k) == "catch":
            k = _skip_ws(text, k + 5, end)
            if text[k] == "(":
                k = _match(text, k, end)
            node.handlers, j = _parse_body(text, k, end)
            k = _skip_ws(text, j, end)
        if _word_at(text, k) == "finally":
            node.finally_, j = _parse_body(text, k + 7, end)
        node.end = j
        return node, j
    j = _stmt_end(text, i, end)
    kind = {"return": "return", "throw": "throw", "const": "decl", "let": "decl",
            "var": "decl", "break": "break", "continue": "continue"}.get(w, "expr")
    if kind == "expr" and re.match(rf"\s*{IDENT}(?:\s*\.\s*{IDENT}|\[[^\]]*\])*\s*[-+*/]?=(?!=)",
                                   text[i:j]):
        kind = "assign"
    return _Node(kind, i, j), max(j, i + 1)


# --- the provider --------------------------------------------------------------------
class ScipGraph:
    """Satisfies the same provider interface the engine reads from `graph.CodeGraph`."""

    def __init__(self, root: str, language: str):
        self.root = root
        self.language = language
        self.functions: dict[str, FunctionNode] = {}
        self.edges: list[CallEdge] = []
        self.decorator_edges: list = []
        self.sources: dict[str, str] = {}
        self.modules: dict[str, str] = {}
        self.classes: dict = {}
        self.trees: dict = {}
        self.imports: dict = {}
        self.build_seconds = 0.0
        self._docs: dict[str, list] = {}           # file -> occurrences
        self._fn_span: dict[str, tuple] = {}       # fq -> (file, body_start, body_end)
        self._bodies: dict[str, FunctionBody] = {}
        self._out: dict[str, list] = {}
        self._in: dict[str, list] = {}

    # interface ----------------------------------------------------------------
    @property
    def source(self):
        return "\n".join(self.sources.values())

    def resolve_name(self, name):
        if name in self.functions:
            return name
        hits = [fq for fq, f in self.functions.items() if f.name == name or f.qualname == name]
        return hits[0] if hits else None

    def get(self, name):
        fq = self.resolve_name(name)
        return self.functions.get(fq) if fq else None

    def edges_from(self, name):
        return list(self._out.get(self.resolve_name(name), []))

    def edges_to(self, name):
        return list(self._in.get(self.resolve_name(name), []))

    def callers_of(self, name):
        return {e.caller for e in self.edges_to(name)}

    def callees_of(self, name):
        return {e.callee_fqname for e in self.edges_from(name) if e.callee_fqname}

    def callees(self, name, depth=2):
        seen, frontier = set(), {self.resolve_name(name)}
        for _ in range(depth):
            nxt = set()
            for f in frontier:
                for c in self.callees_of(f):
                    if c not in seen:
                        seen.add(c)
                        nxt.add(c)
            frontier = nxt
        return seen

    def decorators_of(self, name):
        return []

    def nested_in(self, fq):
        return []

    def roots(self):
        return [fq for fq in self.functions if not self._in.get(fq)]

    def module_constants(self):
        return {}

    def record_dicts(self):
        out = []
        for text in self.sources.values():
            for m in re.finditer(r"\{([^{}]*)\}", text):
                keys = re.findall(rf"({IDENT})\s*:", m.group(1))
                if "id" in keys:
                    out.append(keys)
        return out

    def framework(self):
        text = self.source
        for fw, rx in (("express", r"from\s+['\"]express['\"]|require\(['\"]express['\"]\)"),
                       ("nestjs", r"@nestjs/"), ("spring", r"org\.springframework")):
            if re.search(rx, text):
                return fw
        return "none"

    def body(self, name):
        fq = self.resolve_name(name)
        if fq not in self._bodies:
            self._bodies[fq] = self._build_body(fq)
        return self._bodies[fq]

    # construction -------------------------------------------------------------
    def _offsets(self, file):
        text = self.sources[file]
        starts = [0]
        for i, c in enumerate(text):
            if c == "\n":
                starts.append(i + 1)
        return starts

    def _span_facts(self, fq, a, b, nested):
        """reads, writes, tokens, calls, store_bases for source span [a, b)."""
        file = self._fn_span[fq][0]
        text = self.sources[file]
        starts = self._starts[file]
        seg = text[a:b]
        reads, writes, calls = set(), set(), []
        for occ in self._docs[file]:
            off = starts[occ.range[0]] + occ.range[1]
            if not (a <= off < b) or any(x <= off < y for x, y in nested):
                continue
            end_line, end_col = occ.end
            name = text[off:starts[end_line] + end_col]
            if not re.fullmatch(IDENT, name or ""):
                continue
            ps = parse_symbol(occ.symbol)
            if occ.roles & (ROLE_DEFINITION | ROLE_WRITE) and not occ.roles & ROLE_IMPORT:
                if ps.kind in ("local", "term", "parameter", "unknown"):
                    writes.add(name)
                continue
            k = _skip_ws(text, off + len(name), b)
            if k < b and text[k] == "<":                         # generic call foo<T>(
                k = _skip_ws(text, _match(text, k, b), b)
            if k < b and text[k] == "(" and ps.kind in ("function", "method", "unknown", "term"):
                calls.append(self._callsite(fq, file, text, starts, off, name, ps, k, b, nested))
            else:
                reads.add(name)
        m = re.match(rf"\s*(?:const|let|var)\s+({IDENT})", seg)
        if m:
            writes.add(m.group(1))
        store = set()
        m = re.match(rf"\s*({IDENT})((?:\s*\.\s*{IDENT}|\[[^\]]*\])*)\s*[-+*/]?=(?!=)", seg)
        if m and not re.match(r"\s*(?:const|let|var)\b", seg):
            (store if m.group(2) else writes).add(m.group(1))
        tokens = {t.replace(" ", "") for t in CHAIN_RX.findall(seg)} - KEYWORDS
        tokens |= {t.rsplit(".", 1)[-1] for t in tokens}
        tokens |= {s for g in STRING_RX.findall(seg) for s in g if s}
        for c in calls:
            reads.discard(c.callee_name.split(".")[0])
            reads.update(c.all_reads())
            base = c.receiver.split(".")[0] if c.receiver else ""
            if base and base not in KEYWORDS:
                reads.add(base)
        return reads - KEYWORDS, writes, tokens, calls, store

    def _callsite(self, fq, file, text, starts, off, name, ps, paren, b, nested):
        j = off
        while True:                                 # extend left over `a.b.` receiver chain
            k = j - 1
            while k >= 0 and text[k] in " \t":
                k -= 1
            if k >= 0 and text[k] == ".":
                k -= 1
                while k >= 0 and text[k] in " \t":
                    k -= 1
                s = k
                while s >= 0 and re.match(r"[\w$]", text[s]):
                    s -= 1
                if s < k:
                    j = s + 1
                    continue
            break
        dotted = re.sub(r"\s+", "", text[j:off + len(name)])
        receiver = dotted.rsplit(".", 1)[0] if "." in dotted else ""
        callee = ps.fqname if ps.fqname in self.functions else None
        close = _match(text, paren, b)
        cs = CallSite(dotted, callee, None if ps.kind == "local" else ps.fqname,
                      text[:off].count("\n") + 1, receiver)
        depth, s0 = 0, paren + 1
        for i in range(paren + 1, close):
            c = text[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            if (c == "," and depth == 0) or i == close - 1:
                e = i if c == "," else close - 1
                if text[s0:e].strip():
                    r, w, t, cl, _ = self._span_facts(fq, s0, e, nested)
                    cs.arg_reads.append(frozenset(r))
                    cs.arg_tokens.append(frozenset(t))
                s0 = i + 1
        return cs

    def _build_body(self, fq) -> FunctionBody:
        file, a, b = self._fn_span[fq]
        text = self.sources[file]
        nested = [(x, y) for other, (f2, x, y) in self._fn_span.items()
                  if f2 == file and other != fq and a < x and y <= b]
        nodes = _parse_block(text, a, b)
        stmts = [Stmt(ENTRY, "entry"), Stmt(EXIT, "exit"), Stmt(RAISE, "raise")]
        succ = {ENTRY: set(), EXIT: set(), RAISE: set()}
        loops: list = []

        def new(node, kind, span=None, cond=None):
            s = Stmt(len(stmts), kind, text[:node.start].count("\n") + 1,
                     text[:node.end].count("\n") + 1)
            if span:
                r, w, t, c, store = self._span_facts(fq, span[0], span[1], nested)
                s.reads, s.writes, s.tokens, s.calls, s.store_bases = \
                    frozenset(r), frozenset(w), frozenset(t), c, frozenset(store)
            if cond:
                r, w, t, c, _ = self._span_facts(fq, cond[0], cond[1], nested)
                seg = text[cond[0]:cond[1]]
                s.test_reads, s.test_tokens, s.test_calls = frozenset(r), frozenset(t), c
                ops = set()
                for rx, op in ((r"(?<![!=])===?(?!=)", "eq"), (r"!==?", "ne"), (r"<=", "le"),
                               (r">=", "ge"), (r"(?<![<=!])<(?![=<])", "lt"),
                               (r"(?<![>=])>(?![=>])", "gt"), (r"\binstanceof\b|\bin\b", "in")):
                    if re.search(rx, seg):
                        ops.add(op)
                s.test_ops = frozenset(ops)
                s.test_compares = bool(ops) or bool(c)
            stmts.append(s)
            succ[s.id] = set()
            return s

        def edge(x, y):
            succ.setdefault(x, set()).add(y)

        def seq(ns, preds):
            cur = set(preds)
            for n in ns:
                cur = one(n, cur)
            return cur

        def one(n, preds):
            if n.kind == "block":
                return seq(n.then, preds)
            if n.kind == "if":
                s = new(n, "if", cond=n.cond)
                for p in preds:
                    edge(p, s.id)
                before = len(stmts)
                t_ft = seq(n.then, {s.id})
                heads = [before] if len(stmts) > before else []
                if n.orelse:
                    before = len(stmts)
                    e_ft = seq(n.orelse, {s.id})
                    heads += [before] if len(stmts) > before else []
                    s.branch_heads = tuple(heads)
                    return t_ft | e_ft
                s.branch_heads = tuple(heads) + ("__fallthrough__",)
                return t_ft | {s.id}
            if n.kind == "loop":
                s = new(n, "loop", cond=n.cond)
                s.reads = s.test_reads
                for p in preds:
                    edge(p, s.id)
                loops.append((s.id, []))
                for x in seq(n.then, {s.id}):
                    edge(x, s.id)
                _, breaks = loops.pop()
                return {s.id} | set(breaks)
            if n.kind == "try":
                s = new(n, "try")
                for p in preds:
                    edge(p, s.id)
                out = seq(n.then, {s.id})
                if n.handlers:
                    before = len(stmts)
                    out |= seq(n.handlers, {s.id})
                if n.finally_:
                    out = seq(n.finally_, out)
                return out
            kind = {"decl": "assign", "throw": "raise"}.get(n.kind, n.kind)
            span = (n.start + (len(n.kind) if n.kind in ("return", "throw") else 0), n.end)
            s = new(n, kind if kind in ("assign", "return", "raise", "expr") else "other", span=span)
            for p in preds:
                edge(p, s.id)
            if kind == "return":
                s.returns_value_reads = s.reads
                edge(s.id, EXIT)
                return set()
            if kind == "raise":
                s.denies = True
                edge(s.id, RAISE)
                return set()
            if n.kind == "break" and loops:
                loops[-1][1].append(s.id)
                return set()
            if n.kind == "continue" and loops:
                edge(s.id, loops[-1][0])
                return set()
            return {s.id}

        for x in seq(nodes, {ENTRY}):
            edge(x, EXIT)
        body = FunctionBody(stmts, succ)
        for s in body.stmts:
            if "__fallthrough__" in s.branch_heads:
                explicit = [h for h in s.branch_heads if h != "__fallthrough__"]
                s.branch_heads = tuple(explicit + sorted(body.succ.get(s.id, set()) - set(explicit)))
        return body


def build_from_scip(index_path: str, root: str | None = None) -> ScipGraph:
    t0 = time.perf_counter()
    index_path = Path(index_path)
    root_p = Path(root) if root else index_path.parent
    docs = read_index(index_path)
    lang = next((d.language for d in docs if d.language), "") or \
        {".ts": "typescript", ".js": "javascript", ".java": "java", ".go": "go"}.get(
            Path(docs[0].relative_path).suffix if docs else "", "unknown")
    g = ScipGraph(str(root_p), lang.lower())
    g._starts = {}
    for d in docs:
        file = str(root_p / d.relative_path)
        g.sources[file] = d.text or (root_p / d.relative_path).read_text()
        g._docs[file] = d.occurrences
        g._starts[file] = g._offsets(file)
        g.modules[".".join(Path(d.relative_path).with_suffix("").parts)] = file

    # pass 1: function definitions with an enclosing range
    for file, occs in g._docs.items():
        text, starts = g.sources[file], g._starts[file]
        for occ in occs:
            if not occ.roles & ROLE_DEFINITION or not occ.enclosing_range:
                continue
            ps = parse_symbol(occ.symbol)
            if ps.kind not in ("function", "method"):
                continue
            enc = occ.enclosing_range
            end_line, end_col = (enc[2], enc[3]) if len(enc) == 4 else (enc[0], enc[2])
            ea = starts[enc[0]] + enc[1]
            eb = starts[end_line] + end_col
            off = starts[occ.range[0]] + occ.range[1]
            p = text.find("(", off)
            if p < 0 or p > eb:
                continue
            pclose = _match(text, p, eb)
            brace = text.find("{", pclose)
            if brace < 0 or brace > eb:
                continue
            bclose = _match(text, brace, eb + 1)
            params = []
            for part in re.split(r",(?![^<>{}\[\]()]*[>}\])])", text[p + 1:pclose - 1]):
                m = re.match(rf"\s*(?:public|private|protected|readonly)?\s*\.{{0,3}}({IDENT})", part)
                if m:
                    params.append(m.group(1))
            qual = f"{ps.parent_class}.{ps.name}" if ps.parent_class else ps.name
            g.functions[ps.fqname] = FunctionNode(
                fqname=ps.fqname, name=ps.name, module=ps.module, qualname=qual,
                parent_class=ps.parent_class, file=file,
                lineno=text[:ea].count("\n") + 1, end_lineno=text[:eb].count("\n") + 1,
                params=params, decorators=[], node=None, enclosing=None)
            g._fn_span[ps.fqname] = (file, brace + 1, bclose - 1)

    # pass 2: call edges from each body
    for fq in list(g.functions):
        for s, c in g.body(fq).calls():
            e = CallEdge(fq, c.callee_name, c.callee_fqname, c.lineno, c.callee_symbol)
            g.edges.append(e)
            g._out.setdefault(fq, []).append(e)
            if c.callee_fqname:
                g._in.setdefault(c.callee_fqname, []).append(e)
    g.build_seconds = time.perf_counter() - t0
    return g
