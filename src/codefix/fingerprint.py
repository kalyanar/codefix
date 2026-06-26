"""Fingerprint = path-semantic FACET identity (NOT a structural hash).

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

# Per-class semantic facets (sink category + which guard is missing).
_CLASS_FACETS = {
    "BOLA": ("data_access_by_id", "ownership"),
    "BFLA": ("privileged_mutation", "role"),
    "MISSING_AUTH": ("sensitive_op", "authn"),
    "SSRF": ("url_fetch", "url_validation"),
    "MASS_ASSIGNMENT": ("model_write", "field_allowlist"),
}
# Fix locus implied by the transform (where the guard should go on the path).
_LOCUS = {
    "insert_ownership_guard": "sink_local",
    "insert_role_guard_at_start": "entry_local",
    "insert_authn_guard_at_start": "entry_local",
    "insert_url_validation_before_sink": "sink_local",
    "insert_field_allowlist": "sink_local",
}


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
    # prefer facets stamped by a DetectorSpec; else fall back to the class map
    if finding.sink_category and finding.missing_guard_class:
        sink_category = finding.sink_category
        missing_guard = finding.missing_guard_class
    else:
        sink_category, missing_guard = _CLASS_FACETS.get(
            finding.issue_class, ("unknown", "unknown"))
    return FingerprintKey(
        issue_class=finding.issue_class,
        source_role=finding.source_role or "param",
        sink_category=sink_category,
        missing_guard_class=missing_guard,
        fix_locus=finding.fix_locus or _LOCUS.get(finding.transform_id, "sink_local"),
        framework=framework or "none",
    )
