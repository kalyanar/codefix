"""Developer-extensible catalog — the self-test gate (paper §III.K).

A new defect class (a `DetectorSpec`) is admitted ONLY if it passes a
deterministic, executable gate: schema + vocabulary -> planted-bug detection
(flags its seeded instance, not the safe twin) -> exploit verification of its
fix through the four-stage validator -> structure invariance -> idempotency.
A developer or an LLM proposes the spec; the gate disposes. Only admitted specs
are persisted; a fresh engine then loads and runs them with no code change.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import graph as graphmod
from . import detect, fingerprint, propose
from .detect import DetectorSpec
from .templates import TRANSFORMS
from .validate import verify

VOCAB = {
    "flow": set(detect.FLOWS),
    "source_role": set(detect.SOURCE_ROLES),
    "sink_category": set(detect.SINK_CATEGORIES),
    "missing_guard_class": set(detect.GUARD_CLASSES),
    "fix_locus": set(detect.FIX_LOCI),
}
# every transform in the registry has a renderer, so every one can be gated
KNOWN_TRANSFORMS = set(TRANSFORMS)
DIRECTIONS = set(detect.DIRECTIONS)
MAX_DEPTH = 8   # a spec is untrusted input; an unbounded search is a DoS on big repos


@dataclass
class GateResult:
    admitted: bool
    checks: list[tuple[str, bool, str]]

    def report(self) -> str:
        return "\n".join(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}"
                         for name, ok, detail in self.checks)


def _schema_errors(spec: DetectorSpec) -> list[str]:
    errs = []
    for fld, vocab in VOCAB.items():
        val = getattr(spec, fld)
        if val is None and fld in ("source_role", "fix_locus"):
            continue                           # derived from the detected path
        if val not in vocab:
            errs.append(f"{fld}={val!r} not in vocabulary {sorted(vocab)}")
    if spec.transform_id not in KNOWN_TRANSFORMS:
        errs.append(f"transform_id={spec.transform_id!r} has no renderer")
    if spec.direction not in DIRECTIONS:
        errs.append(f"direction={spec.direction!r} not in {sorted(DIRECTIONS)}")
    if not isinstance(spec.depth, int) or not 1 <= spec.depth <= MAX_DEPTH:
        errs.append(f"depth={spec.depth!r} outside 1..{MAX_DEPTH}")
    for name in ("decorator_anchors", "call_anchors"):
        val = getattr(spec, name)
        if val is not None and not all(isinstance(x, str) and x.replace(".", "_").isidentifier()
                                       for x in val):
            errs.append(f"{name} must be identifiers")
    return errs


def run_gate(spec: DetectorSpec, fixture_dir: str, framework: str = "none") -> GateResult:
    """fixture_dir holds vuln/ safe/ flat/ (each an app) plus exploit.py,
    legit.py and bypass.py."""
    checks: list[tuple[str, bool, str]] = []
    fx = Path(fixture_dir)
    exploit, legit, bypass = str(fx / "exploit.py"), str(fx / "legit.py"), str(fx / "bypass.py")

    errs = _schema_errors(spec)
    checks.append(("schema+vocabulary", not errs, "; ".join(errs) or "valid"))
    if errs:
        return GateResult(False, checks)

    gv = graphmod.build(str(fx / "vuln"))
    fv = detect.detect_with_spec(spec, gv)
    ok_v = len(fv) == 1 and fv[0].issue_class == spec.issue_class
    checks.append(("detect planted bug", ok_v,
                   f"{[f.func for f in fv]}" if ok_v else "planted bug not detected"))
    fs = detect.detect_with_spec(spec, graphmod.build(str(fx / "safe")))
    checks.append(("safe twin not flagged", not fs,
                   "clean" if not fs else f"false positive on {[f.func for f in fs]}"))
    if not ok_v or fs:
        return GateResult(False, checks)

    f = fv[0]
    patch = propose.render(f, spec.transform_id, gv)
    if patch is None:
        checks.append(("exploit-verified fix", False, "fix could not be rendered"))
        return GateResult(False, checks)
    cand = propose.Candidate(None, "authoring", spec.transform_id, 1.0, 1.0, 0, 0,
                             "authoring", patch.diff, patch=patch)
    verdict = verify(f, cand, str(fx / "vuln"), exploit, legit, bypass, graph=gv)
    checks.append(("exploit-verified fix", verdict.status == "success",
                   f"{verdict.status}: {verdict.detail}"))
    if verdict.status != "success":
        return GateResult(False, checks)

    gf = graphmod.build(str(fx / "flat"))
    ff = detect.detect_with_spec(spec, gf)
    fp_v = fingerprint.compute(f, gv, framework).hex()
    inv = bool(ff) and fingerprint.compute(ff[0], gf, framework).hex() == fp_v
    checks.append(("structure-invariant fingerprint", inv,
                   f"flat==nested ({fp_v})" if inv else "fingerprint differs across structure"))
    if not inv:
        return GateResult(False, checks)

    f2 = detect.detect_with_spec(spec, graphmod.build(str(fx / "vuln")))[0]
    idem = fingerprint.compute(f2, gv, framework).hex() == fp_v
    checks.append(("idempotent fingerprint", idem, fp_v))
    return GateResult(idem, checks)


def admit_if_passes(spec, fixture_dir, mem, provenance="llm-authored", framework="none"):
    gate = run_gate(spec, fixture_dir, framework)
    if gate.admitted:
        mem.admit_spec(spec, provenance)
    return gate
