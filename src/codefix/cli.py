"""codefix CLI.

  codefix scan REPO [--db PATH] [--explore] [--pr DIR] [--detect-only | --dry-run] [--apply]

Three operating modes:
  --detect-only  report findings as PR review comments; change nothing; exit 1 when
                 anything is found (CI gating)
  --dry-run      show which fixes would be applied and whether each exploit-verifies
                 (sandbox only); the repository and the memory file are left untouched
  default        render, apply in a sandbox, run all four validator stages, learn, and
                 write a PR draft (evidence checkboxes + the applied diff) per verified
                 fix; --apply also writes verified fixes into the working tree

Reproducers for a real repository are declared in REPO/.codefix/codefix.json (or a
label.json) as {"defects": [{"issue_class", "function", "exploit", "legit", "bypass"}]};
a finding without all four stages is reported as unverified and never applied.

Nightly learning loop (shared memory across repositories):
  0 2 * * * codefix scan /repo --db /shared/codefix.db --explore --pr ./out
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .orchestrate import run_once

APPS = Path(__file__).resolve().parents[2] / "bench" / "apps"
DEFAULT_APP = APPS / "shop_bola"


def _print_run(rep, header):
    print(f"\n=== {header}  app={rep.app} ===")
    for r in rep.results:
        warm = "WARM (from DB)" if r.warm else "COLD (fresh)"
        print(f"  [{r.issue_class}] {r.func}  fp={r.fp_hex}  recall={warm}  "
              f"prior_successes={r.prior_successes}  posterior={r.posterior:.3f}")
        print(f"      src={r.provenance}  tmpl={r.template}  -> {r.status}")
        print(f"      rewritten fix: {r.guard}")
    print(f"  F1: issues={len(rep.results)}  LLM-call-rate={rep.llm_rate:.2f}  "
          f"exploit-verified-success-rate={rep.success_rate:.2f}")


def _review_comment(f) -> str:
    chain = " -> ".join(lv.fqname for lv in f.path)
    return (f"**codefix · {f.issue_class}** in `{f.func}` "
            f"({Path(f.sink_file).name}:{f.sink_lineno})\n\n"
            f"User-controlled `{', '.join(f.tainted_args) or 'input'}` reaches "
            f"`{f.sink_src}` along `{chain}` with no dominating "
            f"{f.missing_guard_class} check. Suggested fix: `{f.transform_id}`.")


def _scan(args) -> int:
    import json
    import shutil
    import tempfile
    from . import detect, graph as graphmod
    from .pr import make_pr_draft
    repo = Path(args.repo).resolve()
    out = Path(args.pr) if args.pr else None
    if out:
        out.mkdir(parents=True, exist_ok=True)

    if args.detect_only:
        g = graphmod.build(str(repo), exclude=graphmod.harness_excluder)
        findings = detect.detect_all(g)
        print(f"codefix: {len(g.sources)} files, {len(g.functions)} functions, "
              f"{len(findings)} finding(s) [{g.build_seconds * 1000:.0f} ms]")
        for i, f in enumerate(findings, 1):
            text = _review_comment(f)
            print(f"\n--- {i}. {Path(f.file_path).relative_to(repo)}:{f.entry_lineno}\n{text}")
            if out:
                (out / f"review_{i}_{f.issue_class}_{f.func}.md").write_text(text + "\n")
        return 1 if findings else 0

    db = args.db
    tmpdir = None
    if args.dry_run:                       # never touch the real memory file
        tmpdir = tempfile.mkdtemp(prefix="codefix_dry_")
        db = str(Path(tmpdir, "memory.db"))
        if Path(args.db).exists():
            shutil.copy(args.db, db)
    try:
        # with --apply, each round applies at most one fix per file and rescans,
        # so later fixes are rendered against the already-patched code
        apply = args.apply and not args.dry_run
        applied, all_results = [], []
        for rnd in range(20):
            rep = run_once(str(repo), db, explore=args.explore, seed=rnd,
                           provider=args.provider, model=args.model, apply=apply)
            if args.events:
                for e in rep.events:
                    print(f"  [{e.phase:11}] {e.target:18} {e.detail}")
            applied += [r for r in rep.results if r.applied]
            all_results = applied + [r for r in rep.results if not r.applied]
            if not apply or not any(r.applied for r in rep.results):
                break
        verified = [r for r in all_results if r.status == "success"]
        print(f"codefix: {len(all_results)} issue(s), {len(verified)} exploit-verified"
              f"{' (dry run: nothing written)' if args.dry_run else ''}")
        for r in all_results:
            verb = ("would apply" if args.dry_run else "applied" if r.applied else "verified") \
                if r.status == "success" else "not applied"
            print(f"  [{r.issue_class}] {r.func}: {r.status} ({r.detail}) — {verb}")
            if r.guard:
                print(f"      fix: {r.guard}")
            if r.status == "success" and out and not args.dry_run:
                draft = make_pr_draft(rep.app, r)
                path = out / f"{rep.app}_{r.issue_class}_{r.func}.md"
                draft.write(str(path))
                print(f"      PR draft -> {path}")
        if out and not args.dry_run:
            (out / "summary.json").write_text(json.dumps([
                {"issue_class": r.issue_class, "function": r.func, "status": r.status,
                 "fingerprint": r.fp_hex, "provenance": r.provenance, "applied": r.applied}
                for r in all_results], indent=2))
        return 0
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="codefix")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan a repository: detect, fix, exploit-verify, learn")
    sc.add_argument("repo")
    sc.add_argument("--db", default=".codefix.db", help="PatchMemory file (share it across repos)")
    sc.add_argument("--explore", action="store_true",
                    help="Thompson sampling (use while fingerprints are young)")
    sc.add_argument("--pr", metavar="DIR", help="write PR drafts / review comments to DIR")
    mode = sc.add_mutually_exclusive_group()
    mode.add_argument("--detect-only", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    sc.add_argument("--apply", action="store_true", help="write verified fixes into the repo")
    sc.add_argument("--provider", default="mock", help="mock | anthropic")
    sc.add_argument("--model", default=None)
    sc.add_argument("--events", action="store_true")

    s = sub.add_parser("scan-bench", help="run the loop over a benchmark app")
    s.add_argument("--app", default=str(DEFAULT_APP))
    s.add_argument("--db", default=".codefixv2.db")
    s.add_argument("--explore", action="store_true")
    s.add_argument("--runs", type=int, default=1)
    s.add_argument("--events", action="store_true", help="print the observable event stream")
    s.add_argument("--pr", metavar="DIR", help="write a PR draft per verified fix to DIR")

    t = sub.add_parser("transfer-demo",
                       help="learn on app A, then warm-start + re-render on app B (F2)")
    t.add_argument("--db", default=".codefixv2_transfer.db")
    t.add_argument("--app-a", default=str(APPS / "shop_bola"))
    t.add_argument("--app-b", default=str(APPS / "library_bola"))

    c = sub.add_parser("coldstart-demo",
                       help="LLM strategy proposes a fix (no template), verified, "
                            "promoted to a template; next codebase warm-starts (F1)")
    c.add_argument("--db", default=".codefixv2_coldstart.db")
    c.add_argument("--app-a", default=str(APPS / "shop_bola"))
    c.add_argument("--app-b", default=str(APPS / "library_bola"))
    c.add_argument("--provider", default="mock", help="mock | anthropic")
    c.add_argument("--model", default=None)

    sub.add_parser("author-demo",
                   help="add a NEW issue class via the self-test gate (admit good, reject bad)")

    args = p.parse_args(argv)

    if args.cmd == "scan":
        return _scan(args)

    if args.cmd == "author-demo":
        from .detect import DetectorSpec
        from .authoring import run_gate
        fx = str(APPS / "new_issue_idor_note")
        import importlib.util
        spec_file = importlib.util.spec_from_file_location("new_detector", fx + "/new_detector.py")
        mod = importlib.util.module_from_spec(spec_file)
        spec_file.loader.exec_module(mod)
        good = mod.SPEC
        bad_enum = DetectorSpec("IDOR_NOTE", "param_to_sink", "insert_ownership_guard",
                                "param", "data_access_by_id", "owner_check", "sink_local")
        bad_flow = DetectorSpec("IDOR_NOTE", "privileged_op", "insert_role_guard_at_start",
                                "param", "privileged_mutation", "role", "entry_local")
        for name, spec in [("VALID spec", good), ("BAD enum (owner_check)", bad_enum),
                           ("WRONG flow (won't detect planted vuln)", bad_flow)]:
            r = run_gate(spec, fx)
            print(f"\n=== {name} ===")
            print(r.report())
            print(f"  => {'ADMITTED' if r.admitted else 'REJECTED'}")
        return 0

    if args.cmd == "scan-bench":
        from pathlib import Path as _P
        from .pr import make_pr_draft
        for i in range(args.runs):
            rep = run_once(args.app, args.db, seed=i, explore=args.explore)
            _print_run(rep, f"run {i + 1}/{args.runs}")
            if args.events:
                print("  events:")
                for e in rep.events:
                    print(f"    [{e.phase:11}] {e.target:14} {e.detail}")
            if args.pr:
                _P(args.pr).mkdir(parents=True, exist_ok=True)
                for r in rep.results:
                    draft = make_pr_draft(rep.app, r)
                    if draft:
                        out = _P(args.pr) / f"{rep.app}_{r.func}.md"
                        draft.write(str(out))
                        print(f"  PR draft -> {out}")
        return 0

    if args.cmd == "coldstart-demo":
        Path(args.db).unlink(missing_ok=True)
        # No built-in templates seeded → `template` strategy is empty → the `llm`
        # strategy fires (fallback chain). LLM-first order makes that explicit.
        print(f"Step 1: app A — NO template; LLM strategy ({args.provider}) proposes")
        ra = run_once(args.app_a, args.db, seed=0, strategies=("template", "llm"),
                      provider=args.provider, model=args.model, seed_builtin=False)
        _print_run(ra, "app A (cold, LLM)")
        print("\nStep 2: app B — LLM's verified fix was promoted to a template")
        rb = run_once(args.app_b, args.db, seed=0, strategies=("template", "llm"),
                      provider=args.provider, model=args.model, seed_builtin=False)
        _print_run(rb, "app B (warm, no LLM)")

        a, b = ra.results[0], rb.results[0]
        print("\n== cold-path -> promote -> warm verdict (F1) ==")
        print(f"  app A used LLM:           {a.llm_used}  (provenance={a.provenance})")
        print(f"  app A exploit-verified:   {a.status == 'success'}")
        print(f"  app B used LLM:           {b.llm_used}  (provenance={b.provenance})")
        print(f"  app B warm from template: {b.warm}")
        print(f"  LLM-call-rate A -> B:     {ra.llm_rate:.2f} -> {rb.llm_rate:.2f}")
        ok = (a.llm_used and a.status == "success"
              and not b.llm_used and b.status == "success")
        print(f"  => COLD-PATH-TO-TEMPLATE {'CONFIRMED' if ok else 'FAILED'}")
        return 0 if ok else 1

    if args.cmd == "transfer-demo":
        Path(args.db).unlink(missing_ok=True)
        print("Step 1: COLD on app A — detect, fix, exploit-verify, LEARN into DB")
        ra = run_once(args.app_a, args.db, seed=0)
        _print_run(ra, "app A (cold)")
        print("\nStep 2: app B — DIFFERENT codebase, SAME defect shape")
        rb = run_once(args.app_b, args.db, seed=0)
        _print_run(rb, "app B (transfer)")

        a, b = ra.results[0], rb.results[0]
        print("\n== transfer verdict (F2) ==")
        print(f"  same fingerprint across A and B:  {a.fp_hex == b.fp_hex}  ({a.fp_hex})")
        print(f"  app B recalled template from DB:  {b.warm}  (prior_successes={b.prior_successes})")
        print(f"  app B used the LLM:               {b.llm_used}")
        print(f"  app B exploit-verified:           {b.status == 'success'}")
        rerendered = a.guard != b.guard
        print(f"  fix rendered for A:               {a.guard!r}")
        print(f"  fix rendered for B:               {b.guard!r}"
              f"   {'(re-rendered)' if rerendered else '(same — same domain)'}")
        # Transfer = recalled from memory, no LLM, and the recalled fix verified
        # on B. Re-rendering to different code is a bonus (shown in the cross-
        # domain demo), not a requirement for transfer.
        ok = (a.fp_hex == b.fp_hex and b.warm and not b.llm_used
              and b.status == "success")
        print(f"  => TRANSFER {'CONFIRMED' if ok else 'FAILED'}")
        return 0 if ok else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
