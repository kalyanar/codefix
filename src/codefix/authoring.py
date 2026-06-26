"""Developer-extensible issue catalog — the self-test gate (M13).

A new issue type (a `DetectorSpec`) is admitted to the catalog ONLY if it passes
a deterministic, executable gate: schema+enum → planted-fixture detection →
exploit verification → structure invariance → idempotency. The LLM (or a
developer) proposes the spec; the gate disposes. Nothing is trusted on its
say-so — a spec that can't catch its own planted bug and remove a real exploit
is rejected.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import graph as graphmod
from . import detect, fingerprint, propose
from .detect import DetectorSpec
from .validate import verify

# Controlled facet vocabulary (curated enum namespace; no free strings).
VOCAB = {
    "flow": {"param_to_sink", "privileged_op"},
    "source_role": {"param", "route_param", "request_body", "header", "query_param"},
    "sink_category": {"data_access_by_id", "privileged_mutation", "url_fetch",
                       "model_write", "sensitive_op"},
    "missing_guard_class": {"ownership", "role", "authn", "url_validation",
                             "field_allowlist"},
    "fix_locus": {"sink_local", "entry_local"},
}
# Transforms with an applier in validate._apply_fix (the TRANSFORMS registry).
KNOWN_TRANSFORMS = {"insert_ownership_guard", "insert_role_guard_at_start"}


@dataclass
class GateResult:
    admitted: bool
    checks: list[tuple[str, bool, str]]   # (name, passed, detail)

    def report(self) -> str:
        lines = [f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}"
                 for name, ok, detail in self.checks]
        return "\n".join(lines)


def _schema_errors(spec: DetectorSpec) -> list[str]:
    errs = []
    for field, vocab in (("flow", VOCAB["flow"]), ("source_role", VOCAB["source_role"]),
                         ("sink_category", VOCAB["sink_category"]),
                         ("missing_guard_class", VOCAB["missing_guard_class"]),
                         ("fix_locus", VOCAB["fix_locus"])):
        val = getattr(spec, field)
        if val not in vocab:
            errs.append(f"{field}={val!r} not in vocabulary {sorted(vocab)}")
    if spec.transform_id not in KNOWN_TRANSFORMS:
        errs.append(f"transform_id={spec.transform_id!r} has no applier")
    return errs


def run_gate(spec: DetectorSpec, fixture_dir: str, framework: str = "none") -> GateResult:
    """Run the full self-test gate. fixture_dir holds vuln/ safe/ flat/ subdirs
    (each an app.py) plus exploit.py and legit.py."""
    checks: list[tuple[str, bool, str]] = []
    fx = Path(fixture_dir)
    exploit, legit = str(fx / "exploit.py"), str(fx / "legit.py")

    # 1. schema + enum
    errs = _schema_errors(spec)
    checks.append(("schema+enum", not errs, "; ".join(errs) or "valid"))
    if errs:
        return GateResult(False, checks)

    # 2. planted-fixture detection: vuln flagged, safe NOT flagged
    gv = graphmod.build(str(fx / "vuln" / "app.py"))
    fv = detect.detect_with_spec(spec, gv)
    ok_v = len(fv) == 1 and fv[0].issue_class == spec.issue_class
    checks.append(("detect planted vuln", ok_v,
                   f"{[f.func for f in fv]}" if ok_v else "vuln not detected"))
    gs = graphmod.build(str(fx / "safe" / "app.py"))
    fs = detect.detect_with_spec(spec, gs)
    checks.append(("safe not flagged", not fs,
                   "clean" if not fs else f"false positive on {[f.func for f in fs]}"))
    if not ok_v or fs:
        return GateResult(False, checks)

    # 3. exploit verification of the paired fix
    f = fv[0]
    cand = propose.Candidate(
        template_id=None, name="authoring", transform_id=spec.transform_id,
        alpha0=1.0, beta0=1.0, successes=0, regressions=0,
        provenance="authoring", rendered_diff=propose.render_fix(f))
    verdict = verify(f, cand, str(fx / "vuln"), exploit, legit)
    checks.append(("exploit-verified fix", verdict.status == "success",
                   f"{verdict.status}: {verdict.detail}"))
    if verdict.status != "success":
        return GateResult(False, checks)

    # 4. structure invariance: flat variant -> same fingerprint
    gf = graphmod.build(str(fx / "flat" / "app.py"))
    ff = detect.detect_with_spec(spec, gf)
    fp_v = fingerprint.compute(f, gv, framework).hex()
    inv = bool(ff) and fingerprint.compute(ff[0], gf, framework).hex() == fp_v
    checks.append(("structure-invariant fingerprint", inv,
                   f"flat==nested ({fp_v})" if inv else "fingerprint differs across structure"))
    if not inv:
        return GateResult(False, checks)

    # 5. idempotency: recompute -> same fingerprint
    f2 = detect.detect_with_spec(spec, graphmod.build(str(fx / "vuln" / "app.py")))[0]
    idem = fingerprint.compute(f2, gv, framework).hex() == fp_v
    checks.append(("idempotent fingerprint", idem, fp_v))

    return GateResult(idem, checks)


def admit_if_passes(spec, fixture_dir, mem, provenance="llm-authored", framework="none"):
    """Run the gate; PERSIST the spec to the catalog only if it passes. The
    full developer-extensible loop: LLM proposes -> gate verifies -> persisted ->
    engine runs it on future runs, no engine code."""
    gate = run_gate(spec, fixture_dir, framework)
    if gate.admitted:
        mem.admit_spec(spec, provenance)
    return gate
