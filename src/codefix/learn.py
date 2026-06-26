"""Selection: greedy or Thompson sampling, on a shared objective.

Both modes use the same informative-prior posterior Beta(alpha0+s, beta0+f),
so the greedy-vs-explore comparison is unconfounded (a fix vs. v1, where
greedy used a different objective than Thompson).
"""
from __future__ import annotations

import random

from .propose import Candidate


def thompson(candidates: list[Candidate], rng: random.Random) -> Candidate:
    def sample(c: Candidate) -> float:
        return rng.betavariate(c.alpha0 + c.successes, c.beta0 + c.regressions)
    return max(candidates, key=sample)


def greedy(candidates: list[Candidate]) -> Candidate:
    return max(candidates, key=lambda c: c.posterior_mean())


def pick(candidates: list[Candidate], explore: bool, rng: random.Random) -> Candidate:
    if not candidates:
        raise ValueError("no candidates")
    return thompson(candidates, rng) if explore else greedy(candidates)
