"""A new defect class, written as data: IDOR on notes.

This literal is the whole contribution a developer (or an LLM) makes. The
self-test gate checks the vocabulary, that it flags its own planted bug in
vuln/ but not the guarded twin in safe/, that its fix is exploit-verified
through all four validator stages, that the flat/ variant gets the same
fingerprint, and that the fingerprint is idempotent. Only then is it persisted
to the detector_specs catalog, where a fresh engine loads and runs it.

No change to the detection engine, the call-graph builder, or the memory store.
"""
from codefix.detect import UP, DetectorSpec, call

SPEC = DetectorSpec(
    issue_class="IDOR_NOTE",
    sink=call("get_note", arg="note_id"),
    missing_guard="ownership",
    search=UP,        # check callers/decorators
    fix_template="insert_ownership_guard",
)
