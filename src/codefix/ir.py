"""Language-neutral function IR consumed by the engine (paper §III.E).

A `CallGraphProvider` (the Python CodeMap, or a SCIP-derived graph) hands the
engine, per function, a list of statements with the facts the analyses need —
names bound and read, call sites, guard tests — plus a statement-level
control-flow graph. The engine never touches a language AST, which is what lets
the same detection run over any provider.

Dominance (Lengauer–Tarjan's relation, computed here with the iterative
Cooper–Harvey–Kennedy scheme) is what makes a guard count: a check clears a use
only if it lies on every path from entry to that use.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ENTRY, EXIT, RAISE = 0, 1, 2


@dataclass
class CallSite:
    """One call (or subscript read, leaf ``__getitem__``) inside a statement."""
    callee_name: str                     # as written: "auth.assert_owns", "ORDERS.get"
    callee_fqname: str | None            # resolved to a function in this graph
    callee_symbol: str | None            # import-qualified symbol ("urllib.request.urlopen")
    lineno: int
    receiver: str = ""                   # dotted receiver text ("Order.objects")
    arg_reads: list = field(default_factory=list)     # per positional arg: frozenset(names)
    arg_tokens: list = field(default_factory=list)    # per positional arg: frozenset(tokens)
    kw_reads: dict = field(default_factory=dict)      # kw name -> frozenset(names)
    kw_tokens: dict = field(default_factory=dict)
    star_kw: frozenset = frozenset()     # names spread with ``**``

    @property
    def leaf(self) -> str:
        return self.callee_name.rsplit(".", 1)[-1]

    def all_reads(self) -> set:
        out: set = set()
        for r in self.arg_reads:
            out |= r
        for r in self.kw_reads.values():
            out |= r
        return out | set(self.star_kw)

    def all_tokens(self) -> set:
        out: set = set()
        for t in self.arg_tokens:
            out |= t
        for t in self.kw_tokens.values():
            out |= t
        return out


@dataclass
class Stmt:
    id: int
    kind: str            # entry exit raise | assign expr if assert loop return raise delete try with other
    lineno: int = 0
    end_lineno: int = 0
    writes: frozenset = frozenset()       # names bound
    reads: frozenset = frozenset()        # names read
    tokens: frozenset = frozenset()       # names, attr chains/leaves, call leaves, str constants
    store_bases: frozenset = frozenset()  # names whose attribute/item is stored (``obj.x = v``)
    calls: list = field(default_factory=list)
    test_reads: frozenset = frozenset()   # if/assert/while test
    test_tokens: frozenset = frozenset()
    test_calls: list = field(default_factory=list)
    test_compares: bool = False           # test contains a comparison or a call
    test_ops: frozenset = frozenset()     # comparison operators in the test: eq ne lt is in ...
    dict_filter: bool = False             # assign of a dict comprehension (allow-list shape)
    denies: bool = False                  # raise, or a call that aborts the request
    returns_value_reads: frozenset = frozenset()
    parent: int | None = None
    region: str | None = None             # which child list of the parent holds it
    branch_heads: tuple = ()              # if/assert: successor ids per branch
    node: object = None                   # provider-specific handle (python ast.stmt)


class FunctionBody:
    """Statements + CFG for one function, with dominance and guard queries."""

    def __init__(self, stmts: list[Stmt], succ: dict[int, set[int]]):
        self.stmts = stmts
        self.succ = succ
        self.pred: dict[int, set[int]] = {s.id: set() for s in stmts}
        for a, bs in succ.items():
            for b in bs:
                self.pred.setdefault(b, set()).add(a)
        self._dom: dict[int, int] | None = None   # id -> bitset of dominators

    # --- lookups -------------------------------------------------------------
    def stmt(self, sid: int) -> Stmt:
        return self.stmts[sid]

    def real(self):
        return [s for s in self.stmts if s.id > RAISE]

    def calls(self):
        for s in self.real():
            for c in s.calls:
                yield s, c
            for c in s.test_calls:
                yield s, c

    # --- dominance -----------------------------------------------------------
    def _rpo(self) -> list[int]:
        seen, order = set(), []
        stack = [(ENTRY, iter(sorted(self.succ.get(ENTRY, ()))))]
        seen.add(ENTRY)
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                order.append(node)
                stack.pop()
            elif nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, iter(sorted(self.succ.get(nxt, ())))))
        return list(reversed(order))

    def _dominators(self) -> dict[int, int]:
        if self._dom is not None:
            return self._dom
        rpo = self._rpo()
        full = 0
        for n in rpo:
            full |= 1 << n
        dom = {n: full for n in rpo}
        dom[ENTRY] = 1 << ENTRY
        changed = True
        while changed:
            changed = False
            for n in rpo:
                if n == ENTRY:
                    continue
                preds = [p for p in self.pred.get(n, ()) if p in dom]
                new = full
                for p in preds:
                    new &= dom[p]
                new |= 1 << n
                if new != dom[n]:
                    dom[n] = new
                    changed = True
        self._dom = dom
        return dom

    def reachable(self, sid: int) -> bool:
        return sid in self._dominators()

    def dominates(self, a: int, b: int) -> bool:
        dom = self._dominators()
        return b in dom and bool(dom[b] >> a & 1)

    def reaches(self, start: int, target: int, avoid=None) -> bool:
        """Is `target` reachable from `start` without passing through `avoid`
        (a statement id or a set of them)?"""
        avoid = set() if avoid is None else ({avoid} if isinstance(avoid, int) else set(avoid))
        if start in avoid:
            return False
        seen, stack = {start}, [start]
        while stack:
            n = stack.pop()
            if n == target:
                return True
            for m in self.succ.get(n, ()):
                if m not in avoid and m not in seen:
                    seen.add(m)
                    stack.append(m)
        return False

    def reachable_from(self, start: int) -> set[int]:
        seen, stack = set(), [start]
        while stack:
            n = stack.pop()
            for m in self.succ.get(n, ()):
                if m not in seen:
                    seen.add(m)
                    stack.append(m)
        return seen

    def guard_protects(self, g: int, u: int) -> bool:
        """Branch-sensitive guard test: the check at `g` dominates `u`, and one of
        its branches can never reach `u` (that branch denies — raises, aborts or
        returns). A check nested in a skippable branch fails dominance; a check
        whose branches both fall through to `u` (it only logs) fails the second
        condition."""
        s = self.stmts[g]
        if not s.branch_heads or not self.dominates(g, u):
            return False
        if g == u:
            return True
        return any(not self.reaches(h, u, avoid=g) for h in s.branch_heads)

    def call_dominates(self, c: int, u: int) -> bool:
        """A statement-level guard call (``assert_owns(obj)``) protects `u` when
        it dominates it."""
        return self.dominates(c, u)

    def reaching_defs(self, name: str, at: int) -> tuple[list, bool]:
        """Definitions of `name` that reach statement `at`, and whether the value
        on function entry (a parameter) also reaches it."""
        defs = [s for s in self.real() if name in s.writes]
        ids = {d.id for d in defs}
        reaching = [d for d in defs if d.id != at and any(
            self.reaches(m, at, avoid=ids - {d.id}) or m == at for m in self.succ.get(d.id, ()))]
        from_entry = self.reaches(ENTRY, at, avoid=ids - {at}) if at not in ids else \
            self.reaches(ENTRY, at, avoid=ids - {at})
        return reaching, from_entry

    def normal_exit(self) -> int:
        return EXIT

    def uses_of(self, name: str, after: int) -> list[int]:
        """Statements reachable from `after` that read `name` (or store into it)."""
        reach = self.reachable_from(after)
        return [s.id for s in self.real()
                if s.id in reach and s.id != after
                and (name in s.reads or name in s.store_bases or name in s.test_reads)]
