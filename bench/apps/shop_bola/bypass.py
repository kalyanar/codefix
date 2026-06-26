"""Adversarial bypass: variant non-owner accesses that must ALL be blocked.
Catches overfit fixes (e.g. one that only blocks a specific attacker/victim).
Exit 0 => all blocked (robust). Exit !=0 => a bypass succeeded.
(Hand-authored stand-in for an LLM red-team agent.)"""
import sys
def main():
    d = sys.argv[sys.argv.index("--app")+1]; sys.path.insert(0, d); import app
    # (attacker_uid, victim_order_id) pairs the fix must block
    attacks = [(1, 2), (2, 1)]
    for atk, victim in attacks:
        app.login(atk)
        try:
            o = app.get_order(victim)
        except PermissionError:
            continue                  # blocked — good
        if o is not None and o.get("user_id") != atk:
            print(f"BYPASS: attacker {atk} read order {victim} ({o})"); return 1
    print("all variant attacks blocked"); return 0
sys.exit(main())
