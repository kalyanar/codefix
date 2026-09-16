"""Four-stage exploit-verified validation (paper §III.G).

A proposed fix is a hypothesis. It is applied to a sandboxed copy of the
codebase and must pass ALL four stages:

  1. exploit      — the real attack, replayed against the patched code, is blocked
                    (it must first succeed on the unpatched code: ground truth);
  2. differential — the legitimate request the true owner makes still succeeds;
  3. contract     — the legitimate response keeps its schema (every key, every
                    value type); a fix that silently drops a field is rejected;
  4. adversarial  — a second, varied attacker (different principal / object /
                    payload) is also blocked, catching fixes overfit to one victim.

Harness convention, per app: ``exploit.py`` (exit 0 = attack worked),
``legit.py`` (exit 0 = owner path works; prints ``CONTRACT <json>`` with the
response it received) and ``bypass.py`` (exit 0 = every variant blocked), each
run as ``python <script> --app <dir>``. A missing stage is not a pass: the fix is
``unverified``, which applies nothing, remembers nothing and opens no PR.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

STAGES = ("exploit-blocked", "differential-legit", "contract-conformance", "adversarial-bypass")
# statuses that are verified outcomes (move the posterior); the rest are not
VERIFIED_STATUSES = ("success", "regression")


@dataclass
class Verdict:
    status: str          # success | regression | no_repro | unverified | render_failed
    detail: str
    stages: list = field(default_factory=list)   # [(name, passed)]


def _run(script: str, app_dir: str, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, script, "--app", app_dir],
                          capture_output=True, text=True, timeout=timeout)


def response_schema(value):
    """Structural schema of a JSON value: keys and value types, recursively."""
    if isinstance(value, dict):
        return {k: response_schema(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [response_schema(value[0])] if value else []
    if value is None:
        return "null"
    return type(value).__name__


def schema_violations(before, after, path="$") -> list[str]:
    """What the patched response lost or retyped relative to the original."""
    out = []
    if isinstance(before, dict):
        if not isinstance(after, dict):
            return [f"{path}: object became {after!r}"]
        for k, v in before.items():
            if k not in after:
                out.append(f"{path}.{k}: field removed")
            else:
                out += schema_violations(v, after[k], f"{path}.{k}")
    elif isinstance(before, list):
        if not isinstance(after, list):
            out.append(f"{path}: array became {after!r}")
        elif before and after:
            out += schema_violations(before[0], after[0], f"{path}[0]")
    elif before != after and "null" not in (before, after):
        out.append(f"{path}: {before} became {after}")
    return out


def _contract(proc: subprocess.CompletedProcess):
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("CONTRACT "):
            try:
                return response_schema(json.loads(line[len("CONTRACT "):]))
            except json.JSONDecodeError:
                return None
    return None


def verify(finding, candidate, app_dir: str, exploit: str, legit: str,
           bypass: str | None = None, graph=None) -> Verdict:
    app_dir = str(Path(app_dir).resolve())
    bypass = bypass or str(Path(app_dir, "bypass.py"))
    patch = getattr(candidate, "patch", None)
    if patch is None:
        from . import graph as graphmod
        from .templates import RenderError, render_patch
        try:
            patch = render_patch(candidate.transform_id, finding, graph or graphmod.build(app_dir, exclude=graphmod.harness_excluder))
        except (RenderError, SyntaxError, KeyError) as e:
            return Verdict("render_failed", str(e))
    for name, script in (("exploit", exploit), ("legit", legit)):
        if not Path(script).exists():
            return Verdict("unverified", f"no {name} reproducer")

    # ground truth: the attack works and the owner path + contract are observable
    if _run(exploit, app_dir).returncode != 0:
        return Verdict("no_repro", "exploit did not succeed on the unpatched code")
    base_legit = _run(legit, app_dir)
    base_contract = _contract(base_legit)

    sandbox = Path(tempfile.mkdtemp(prefix="codefix_sbx_"))
    stages: list = []
    try:
        dst = sandbox / "app"
        shutil.copytree(app_dir, dst, ignore=shutil.ignore_patterns("__pycache__"))
        patch.write_to(str(dst))
        dst = str(dst)

        ok = _run(exploit, dst).returncode != 0
        stages.append(("exploit-blocked", ok))
        if not ok:
            return Verdict("regression", "exploit still succeeds after the patch", stages)

        after_legit = _run(legit, dst)
        ok = after_legit.returncode == 0
        stages.append(("differential-legit", ok))
        if not ok:
            return Verdict("regression", "patch broke the legitimate path", stages)

        if base_contract is None:
            stages.append(("contract-conformance", False))
            return Verdict("unverified", "legit reproducer emitted no CONTRACT response", stages)
        after_contract = _contract(after_legit)
        lost = ["no CONTRACT emitted after patch"] if after_contract is None else \
            schema_violations(base_contract, after_contract)
        stages.append(("contract-conformance", not lost))
        if lost:
            return Verdict("regression", "response contract broken: " + "; ".join(lost), stages)

        if not Path(bypass).exists():
            stages.append(("adversarial-bypass", False))
            return Verdict("unverified", "no adversarial reproducer (bypass.py)", stages)
        ok = _run(bypass, dst).returncode == 0
        stages.append(("adversarial-bypass", ok))
        if not ok:
            return Verdict("regression", "an adversarial variant defeated the patch", stages)

        return Verdict("success", "all four stages pass", stages)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
