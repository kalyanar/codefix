"""codefix v2 CLI — slice entrypoint.

  codefix scan-bench [--app DIR] [--db PATH] [--explore] [--runs N]

Running the bundled BOLA app end-to-end produces F1's first data point:
provenance, LLM-call rate, and exploit-verified success rate.
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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="codefix")
    sub = p.add_subparsers(dest="cmd", required=True)

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

    if args.cmd == "author-demo":
        from .detect import DetectorSpec
        from .authoring import run_gate
        fx = str(APPS / "new_issue_idor_note")
        good = DetectorSpec("IDOR_NOTE", "param_to_sink", "insert_ownership_guard",
                            "param", "data_access_by_id", "ownership", "sink_local")
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
            rep = run_once(args.app, args.db, seed=i)
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
