"""M9 — contrastive embedding (feature-flagged, pure-Python, no ML deps).

M7's embedding HARDCODES which facets matter (it uses class/sink/guard, excludes
framework). M9 LEARNS feature relevance from exploit-verified outcomes:

  * positive pair  = two fingerprints where the SAME fix verified on both
                     (the fix transferred)        -> their differing features are
                     IRRELEVANT to transfer       -> down-weight them (pull close)
  * negative pair  = a fix that verified on one but REGRESSED on the other
                     (looked similar, didn't transfer) -> their differing features
                     PREDICT non-transfer          -> up-weight them (push apart)

Labels come free from the outcome memory; nothing is hand-labelled. The result:
fuzzy recall (M7) borrows a fix only across fingerprints where history says it
actually transfers. Gated by a feature flag — OFF falls back to the deterministic
M7 embedding, so the system can run fully deterministic and the effect is ablatable.
"""
from __future__ import annotations

import hashlib
import json
import os

EMB_DIM = 32


def enabled(flag: bool | None = None) -> bool:
    """Feature flag. Explicit arg wins; else env CODEFIX_CONTRASTIVE=1; else OFF."""
    if flag is not None:
        return flag
    return os.environ.get("CODEFIX_CONTRASTIVE", "0") == "1"


def _h(s: str) -> int:
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:4], "big")


def tokenize(issue_class, sink_category, missing_guard_class, framework="", context=""):
    """Feature tokens for a fingerprint. Includes framework + context — which the
    learner may up- or down-weight based on outcomes (M7 hardcodes their relevance)."""
    toks = {f"class:{issue_class}", f"sink:{sink_category}", f"guard:{missing_guard_class}"}
    if framework:
        toks.add(f"fw:{framework}")
    if context:
        toks.add(f"ctx:{context}")
    return toks


class ContrastiveEmbedder:
    """Learnable per-feature weights. embed() weights each token's contribution;
    train() adjusts weights from labelled pairs. A simple, interpretable
    contrastive update (not SGD on a formal loss) — enough to demonstrate the
    mechanism and stay dependency-free."""

    def __init__(self, lr: float = 0.3):
        self.w: dict[str, float] = {}
        self.lr = lr

    def weight(self, t: str) -> float:
        return self.w.get(t, 1.0)

    def embed(self, tokens) -> list[float]:
        v = [0.0] * EMB_DIM
        for t in tokens:
            v[_h(t) % EMB_DIM] += self.weight(t)
        n = sum(x * x for x in v) ** 0.5 or 1.0
        return [x / n for x in v]

    def cosine(self, ta, tb) -> float:
        a, b = self.embed(ta), self.embed(tb)
        return sum(x * y for x, y in zip(a, b))

    def train(self, pairs, epochs: int = 30):
        """pairs: list of (tokensA, tokensB, label) with label +1 (transferred ->
        close) or -1 (regressed -> far). Distinguishing tokens of a NEGATIVE pair
        are up-weighted (they predict non-transfer); of a POSITIVE pair are
        down-weighted (irrelevant to transfer)."""
        for _ in range(epochs):
            for ta, tb, label in pairs:
                for t in set(ta) ^ set(tb):              # symmetric difference
                    step = self.lr if label < 0 else -self.lr
                    self.w[t] = max(0.0, self.weight(t) + step)

    def to_json(self) -> str:
        return json.dumps(self.w)

    def load_json(self, s: str):
        self.w = json.loads(s)


def mine_pairs(mem):
    """Harvest (fp_a, fp_b, label) pairs from the outcome memory: a template that
    succeeded on two fingerprints -> positive; succeeded on one and regressed on
    another -> negative. (Slice helper; the demo also constructs pairs directly.)"""
    rows = mem.conn.execute(
        "SELECT l.template_id, l.fingerprint_id, l.successes, l.regressions FROM links l"
    ).fetchall()
    by_t: dict[int, list] = {}
    for r in rows:
        by_t.setdefault(r["template_id"], []).append(r)
    pairs = []
    for _, ls in by_t.items():
        for i in range(len(ls)):
            for j in range(i + 1, len(ls)):
                a, b = ls[i], ls[j]
                a_ok = a["successes"] > 0 and a["regressions"] == 0
                b_ok = b["successes"] > 0 and b["regressions"] == 0
                if a_ok and b_ok:
                    pairs.append((a["fingerprint_id"], b["fingerprint_id"], +1))
                elif (a_ok and b["regressions"] > 0) or (b_ok and a["regressions"] > 0):
                    pairs.append((a["fingerprint_id"], b["fingerprint_id"], -1))
    return pairs
