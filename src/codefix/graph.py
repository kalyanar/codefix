"""Minimal single-module code graph (slice scope).

Enough structure for Tier-0/Tier-1 detection: functions, in-module call
edges, parameter sets, and helpers to walk callees to a bounded depth.
A full multi-module CodeGraph + CFG is milestone M3.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FunctionNode:
    name: str
    node: ast.FunctionDef
    params: list[str]
    lineno: int
    decorators: list[str] = field(default_factory=list)  # up-the-chain guards


@dataclass
class CodeGraph:
    functions: dict[str, FunctionNode]
    # name -> set of in-module function names it calls
    calls: dict[str, set[str]]
    source: str
    file_path: str

    def callers_of(self, name: str) -> set[str]:
        return {c for c, callees in self.calls.items() if name in callees}

    def roots(self) -> list[str]:
        """Functions with no in-module caller (entry points / routes)."""
        return [n for n in self.functions if not self.callers_of(n)]

    def callees(self, name: str, depth: int = 2) -> set[str]:
        seen: set[str] = set()
        frontier = {name}
        for _ in range(depth):
            nxt: set[str] = set()
            for f in frontier:
                for c in self.calls.get(f, set()):
                    if c not in seen:
                        seen.add(c)
                        nxt.add(c)
            frontier = nxt
        return seen


def _called_names(fn: ast.FunctionDef) -> set[str]:
    out: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _decorator_names(fn: ast.FunctionDef) -> list[str]:
    names: list[str] = []
    for d in fn.decorator_list:
        if isinstance(d, ast.Name):
            names.append(d.id)
        elif isinstance(d, ast.Attribute):
            names.append(d.attr)
        elif isinstance(d, ast.Call):
            f = d.func
            if isinstance(f, ast.Name):
                names.append(f.id)
            elif isinstance(f, ast.Attribute):
                names.append(f.attr)
    return names


def build(file_path: str) -> CodeGraph:
    source = Path(file_path).read_text()
    tree = ast.parse(source)
    functions: dict[str, FunctionNode] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in node.args.args]
            functions[node.name] = FunctionNode(
                node.name, node, params, node.lineno, _decorator_names(node))
    calls: dict[str, set[str]] = {}
    for name, fn in functions.items():
        called = _called_names(fn.node)
        calls[name] = {c for c in called if c in functions}
    return CodeGraph(functions=functions, calls=calls, source=source, file_path=file_path)
