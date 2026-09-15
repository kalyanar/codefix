"""Fingerprint = path-semantic FACET identity (NOT a structural hash) — paper §III.D.

The identity is a tuple of meaningful facets derived from the entry->sink path,
deliberately NOT encoding the exact call-chain shape. So a flat (inlined sink)
and a nested (sink-in-helper) version of the same defect produce the SAME key
and transfer — which a topology hash could not do. The .hex() is just a compact
encoding of the tuple, not a hash of code structure.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .graph import CodeGraph
from .detect import Finding

@dataclass(frozen=True)
class FingerprintKey:
    issue_class: str          # = detector_id for the slice
    source_role: str
    sink_category: str
    missing_guard_class: str
    fix_locus: str
    framework: str

    def hex(self) -> str:
        blob = "|".join((self.issue_class, self.source_role, self.sink_category,
                         self.missing_guard_class, self.fix_locus, self.framework))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


# --- L5 embedding + L4 precondition bitmask (M7: fuzzy recall) ----------------
# The embedding is over the framework-INDEPENDENT semantic facets, so two
# instances of the same defect that differ only in framework (exact-key miss)
# land at cosine 1.0 and recall each other's fix. (Contrastive training of this
# embedding is M9; here it's a deterministic feature vector.)
EMB_DIM = 32
_PRECOND_BIT = {"authn": 1, "owns": 2, "validated": 4, "sanitized": 8}
_GUARD_TO_PRECOND = {"ownership": "owns", "role": "owns", "authn": "authn",
                     "url_validation": "validated", "field_allowlist": "sanitized"}


def _stable_hash(s: str) -> int:
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:4], "big")


def embedding(key: "FingerprintKey") -> list[float]:
    v = [0.0] * EMB_DIM
    for f in (f"class:{key.issue_class}", f"sink:{key.sink_category}",
              f"guard:{key.missing_guard_class}"):
        v[_stable_hash(f) % EMB_DIM] += 1.0
    norm = sum(x * x for x in v) ** 0.5 or 1.0
    return [x / norm for x in v]


def precondition_mask(key: "FingerprintKey") -> int:
    """Bitmask of preconditions ENFORCED at the site; the missing guard's bit is
    0, the rest assumed present. Same missing precondition -> same mask (Hamming
    0), so it filters fuzzy candidates to the right defect family."""
    missing = _GUARD_TO_PRECOND.get(key.missing_guard_class)
    mask = 0
    for name, bit in _PRECOND_BIT.items():
        if name != missing:
            mask |= bit
    return mask


def compute(finding: Finding, graph: CodeGraph, framework: str) -> FingerprintKey:
    """Alg. 3: every facet is read off the detected entry-to-sink path — the
    source role from the taint origin, the sink category from the matched sink
    predicate, the missing-guard class from the unsatisfied mitigation, the fix
    locus from where a dominating guard must be inserted. None of them depends
    on call depth, helper count or identifier names."""
    return FingerprintKey(
        issue_class=finding.issue_class,
        source_role=finding.source_role or "none",
        sink_category=finding.sink_category,
        missing_guard_class=finding.missing_guard_class,
        fix_locus=finding.fix_locus or "handler",
        framework=framework or "none",
    )


def label(key: FingerprintKey, finding: Finding | None = None) -> str:
    """Human-readable fingerprint label for PRs (``bola/nested/ownership``); the
    shape word is descriptive only and is not part of the key."""
    shape = "nested" if finding is not None and len(finding.path) > 1 else "flat"
    return f"{key.issue_class.lower()}/{shape}/{key.missing_guard_class}"
