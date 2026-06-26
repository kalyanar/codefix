"""The validator stack (slice: exploit + differential).

This is the part that makes codefix not-a-cache: a candidate fix is recorded
as a success ONLY if it is exploit-verified.

  1. exploit reproducer: succeeds on the unpatched app, must FAIL after patch
  2. differential behaviour: the legitimate path must still PASS after patch

(Contract conformance + adversarial bypass are milestone M2's full form.)
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .detect import Finding
from .propose import Candidate


@dataclass
class Verdict:
    status: str          # 'success' | 'regression' | 'no_repro'
    detail: str
    stages: list = None  # [(name, passed)] per validator stage

    def __post_init__(self):
        if self.stages is None:
            self.stages = []


def _run(script: str, app_dir: str) -> int:
    return subprocess.run([sys.executable, script, "--app", app_dir],
                          capture_output=True, text=True).returncode


def _run_capture(script: str, app_dir: str) -> str:
    return subprocess.run([sys.executable, script, "--app", app_dir],
                          capture_output=True, text=True).stdout.strip()


def _apply_fix(app_py: Path, finding: Finding, transform_id: str) -> bool:
    lines = app_py.read_text().splitlines(keepends=True)
    idx = finding.sink_lineno - 1
    ref = lines[idx]
    indent = ref[: len(ref) - len(ref.lstrip())]

    if transform_id == "insert_ownership_guard":
        obj, of = finding.sink_assign_target, finding.owner_field
        guard = (
            f'{indent}if {obj} is not None and {obj}["{of}"] != current_user_id():\n'
            f'{indent}    raise PermissionError("not owner")\n'
        )
        lines.insert(idx + 1, guard)          # after the sink assignment
    elif transform_id == "insert_role_guard_at_start":
        guard = (
            f'{indent}if current_user() is None or current_user().get("role") != "admin":\n'
            f'{indent}    raise PermissionError("forbidden")\n'
        )
        lines.insert(idx, guard)              # before the first body statement
    elif transform_id == "insert_field_allowlist":
        dv = finding.sink_assign_target
        allow = f'{indent}{dv} = {{k: {dv}[k] for k in ALLOWED_FIELDS if k in {dv}}}\n'
        lines.insert(idx, allow)              # filter the dict before the **kwargs sink
    elif transform_id == "insert_url_validation_before_sink":
        url = finding.sink_assign_target
        guard = (f'{indent}if not is_safe_url({url}):\n'
                 f'{indent}    raise PermissionError("blocked url")\n')
        lines.insert(idx, guard)              # validate the URL before the fetch
    elif transform_id == "insert_authn_guard_at_start":
        guard = (f'{indent}if current_user() is None:\n'
                 f'{indent}    raise PermissionError("authentication required")\n')
        lines.insert(idx, guard)              # require authentication before the body
    else:
        return False
    app_py.write_text("".join(lines))
    return True


def verify(finding: Finding, candidate: Candidate, app_dir: str,
           exploit: str, legit: str) -> Verdict:
    """The validator stack (M2). A fix is `success` only if ALL applicable
    stages pass:
      1. exploit reproducer  — succeeds before, FAILS after
      2. differential        — legitimate path still PASSES
      3. contract conformance— legitimate response unchanged before vs after
                               (optional: needs app's contract.py)
      4. adversarial bypass  — every variant attack still BLOCKED
                               (optional: needs app's bypass.py; the red-team's
                                generated attack set — LLM-authored in prod, here
                                a hand-authored stand-in)
    """
    stages = []
    # 1. confirm the exploit works on the unpatched app (ground truth)
    if _run(exploit, app_dir) != 0:
        return Verdict("no_repro", "exploit did not succeed on unpatched app")

    sandbox = Path(tempfile.mkdtemp(prefix="codefix_sbx_"))
    try:
        dst = sandbox / "app"
        shutil.copytree(app_dir, dst)
        if not _apply_fix(dst / "app.py", finding, candidate.transform_id):
            return Verdict("no_repro", f"no applier for transform {candidate.transform_id}")
        dst = str(dst)

        # 1. exploit must now FAIL
        ok_exploit = _run(exploit, dst) != 0
        stages.append(("exploit-blocked", ok_exploit))
        # 2. differential: legit must still PASS
        ok_legit = _run(legit, dst) == 0
        stages.append(("differential-legit", ok_legit))
        if not ok_exploit:
            return Verdict("regression", "exploit still succeeds after patch", stages)
        if not ok_legit:
            return Verdict("regression", "patch broke the legitimate path", stages)

        # 3. contract conformance (optional): owner response unchanged
        contract = Path(app_dir, "contract.py")
        if contract.exists():
            same = _run_capture(str(contract), app_dir) == _run_capture(str(contract), dst)
            stages.append(("contract-conformance", same))
            if not same:
                return Verdict("regression", "patch changed the legitimate response (contract)", stages)

        # 4. adversarial bypass (optional): all variant attacks blocked
        bypass = Path(app_dir, "bypass.py")
        if bypass.exists():
            robust = _run(str(bypass), dst) == 0
            stages.append(("adversarial-bypass", robust))
            if not robust:
                return Verdict("regression", "adversarial bypass defeated the patch", stages)

        passed = ", ".join(n for n, ok in stages if ok)
        return Verdict("success", f"all stages pass: {passed}", stages)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
