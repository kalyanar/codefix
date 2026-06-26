"""Intra-procedural def-use taint propagation (M3).

The slice's original detection only saw a parameter flowing *directly* into a
sink call. Real code threads the tainted value through intermediate assignments,
attribute access, and call returns:

    def get_order(order_id):
        oid = order_id           # taint hop 1
        key = oid                # taint hop 2
        order = fetch(key)       # sink uses `key`, not the param

A direct-reference check misses this (false negative). This module computes the
fixpoint set of *all* values derived from the tainted sources, so the sink check
sees `key` as tainted. This is the def-use / dataflow precision reviewers asked
for (handles assignment chains, attribute access, and call-arg propagation).
"""
from __future__ import annotations

import ast


def _expr_is_tainted(expr: ast.expr, tainted: set[str]) -> bool:
    """True if any name read in `expr` is tainted (covers x, x.attr, f(x), x[i])."""
    return any(isinstance(c, ast.Name) and c.id in tainted for c in ast.walk(expr))


def tainted_values(fn_node: ast.AST, sources: set[str]) -> set[str]:
    """Fixpoint: every variable derived (transitively) from a tainted source.

    Handles `x = <tainted ...>`, `x: T = <tainted>`, and `x += <tainted>`.
    Conservative on call returns: `x = f(tainted)` taints `x`.
    """
    tainted = set(sources)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn_node):
            tgt = val = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                tgt, val = node.targets[0].id, node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                    and node.value is not None:
                tgt, val = node.target.id, node.value
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                tgt, val = node.target.id, node.value
            if tgt and tgt not in tainted and val is not None and _expr_is_tainted(val, tainted):
                tainted.add(tgt)
                changed = True
    return tainted
