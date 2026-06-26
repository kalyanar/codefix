"""LLM provider abstraction for the `llm` proposer strategy.

Configurable: `mock` (deterministic, no key — for tests/repro) or `anthropic`
(real Claude, model configurable, lazy-imported). Any provider that can't run
(no key, no network, import error) returns None so the template fallback wins —
graceful degradation, never a hard failure.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Protocol

from .detect import Finding

# Transforms the LLM is allowed to choose from (grounded, not freeform) — the
# full authz-family set the engine supports.
ALLOWED_TRANSFORMS = (
    "insert_ownership_guard",            # BOLA
    "insert_role_guard_at_start",        # BFLA
    "insert_field_allowlist",            # mass assignment
    "insert_url_validation_before_sink", # SSRF
    "insert_authn_guard_at_start",       # missing auth
)


@dataclass
class FixProposal:
    transform_id: str
    rationale: str


class LLMProvider(Protocol):
    name: str
    def propose(self, finding: Finding) -> FixProposal | None: ...


class MockLLMProvider:
    """Deterministic canned proposer. Proposes the canonical guard transform for
    the issue class. Stands in for a real model so the strategy/fallback/promote
    machinery is exercised reproducibly without a key. Swap for `anthropic` for
    real proposals."""
    name = "mock"

    def propose(self, finding: Finding) -> FixProposal | None:
        if finding.transform_id in ALLOWED_TRANSFORMS:
            return FixProposal(finding.transform_id,
                               f"insert {finding.issue_class} guard on the path")
        return None


class AnthropicProvider:
    """Real Claude provider. Model configurable; lazy-imports the SDK; reads
    ANTHROPIC_API_KEY. Returns None on any failure (→ template fallback)."""
    name = "anthropic"

    def __init__(self, model: str | None = None, api_key: str | None = None):
        self.model = model or os.environ.get("CODEFIX_LLM_MODEL", "claude-sonnet-4-6")
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    def propose(self, finding: Finding) -> FixProposal | None:
        if not self.api_key:
            return None
        try:
            import anthropic  # type: ignore
        except Exception:
            return None
        prompt = (
            "You are a security-fix proposer. Choose exactly one transform_id to "
            "remediate the described defect, on the call path.\n"
            f"issue_class: {finding.issue_class}\n"
            f"function: {finding.func}\n"
            f"sink: {finding.sink_src}\n"
            f"allowed transform_id: {list(ALLOWED_TRANSFORMS)}\n"
            'Respond with ONLY JSON: {"transform_id": "..."}'
        )
        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            msg = client.messages.create(
                model=self.model, max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(getattr(b, "text", "") for b in msg.content)
            m = re.search(r"\{.*\}", text, re.S)
            tid = json.loads(m.group(0))["transform_id"] if m else None
            if tid in ALLOWED_TRANSFORMS:
                return FixProposal(tid, "claude proposal")
        except Exception:
            return None
        return None


def resolve_provider(name: str, model: str | None = None) -> LLMProvider:
    if name == "anthropic":
        return AnthropicProvider(model=model)
    return MockLLMProvider()
