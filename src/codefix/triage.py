"""M10 — triage agent (scoping, NON-GATING).

A triage step reads the repo and emits tags that PRIORITIZE which detector classes
to run first and produce an explanation. Critical invariant: triage **never
gates** — the full deterministic detector sweep always runs, so recall is
unchanged; triage only reduces cost-to-first-finding (and, at scale, lets the
expensive analyses run on the likely classes first). Even WRONG tags cannot cause
a miss, because the priority is always a permutation of ALL classes, not a subset.

The tag emitter here is a deterministic mock (source-signal heuristics) standing
in for an LLM that reads an architecture summary — same swap pattern as the LLM
provider. The constraint (non-gating) holds regardless of how smart the tagger is.
"""
from __future__ import annotations

from .detect import ALL_CLASSES

# (signals in source) -> (likely class, human tag). Mock for the LLM arch reader.
_SIGNALS = [
    (("fetch_url", "urlopen", "urlretrieve", "http_fetch"), "SSRF", "accepts-urls"),
    (("transfer", "charge", "payout", "wire", "send_money"), "MISSING_AUTH", "handles-payments"),
    (("wipe", "admin_delete", ".pop(", ".remove("), "BFLA", "admin/destructive-ops"),
    (("build_user(**", "(**data", "(**request", "(**kw"), "MASS_ASSIGNMENT", "model-binding"),
    (("owner_id", "user_id", "get_order_by_id", "lookup_record"), "BOLA", "object-by-id"),
]


def triage_tags(source: str):
    """Return [(tag, likely_class)] for signals present in the source."""
    return [(tag, cls) for sigs, cls, tag in _SIGNALS if any(s in source for s in sigs)]


def class_priority(tags) -> list[str]:
    """Predicted classes first, then the REST of ALL_CLASSES appended — so the
    result is always a full permutation (non-gating)."""
    order, seen = [], set()
    for _, cls in tags:
        if cls not in seen:
            seen.add(cls)
            order.append(cls)
    for cls in ALL_CLASSES:
        if cls not in seen:
            seen.add(cls)
            order.append(cls)
    return order


def explain(tags) -> str:
    if not tags:
        return "no triage signals; running full sweep in default order"
    return "triage tags: " + ", ".join(f"{t}→{c}" for t, c in tags)
