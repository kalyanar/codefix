"""The three operating modes of ``codefix scan`` (site: Integration)."""
import shutil
import sqlite3
from pathlib import Path

from codefix.cli import main

APPS = Path(__file__).resolve().parents[1] / "bench" / "apps"


def _repo(tmp_path, app="shop_multifile"):
    dst = tmp_path / "repo"
    shutil.copytree(APPS / app, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def _tree(root):
    return {p.relative_to(root): p.read_text() for p in sorted(root.rglob("*.py"))}


def test_detect_only_reports_review_comments_and_changes_nothing(tmp_path, capsys):
    repo = _repo(tmp_path)
    before = _tree(repo)
    rc = main(["scan", str(repo), "--detect-only", "--pr", str(tmp_path / "out"),
               "--db", str(tmp_path / "m.db")])
    assert rc == 1                                        # findings -> CI gate fails
    comments = list((tmp_path / "out").glob("review_*.md"))
    assert len(comments) == 1 and "BOLA" in comments[0].read_text()
    assert _tree(repo) == before and not (tmp_path / "m.db").exists()


def test_dry_run_verifies_in_sandbox_without_writing(tmp_path, capsys):
    repo = _repo(tmp_path)
    before = _tree(repo)
    rc = main(["scan", str(repo), "--dry-run", "--db", str(tmp_path / "m.db"),
               "--pr", str(tmp_path / "out")])
    out = capsys.readouterr().out
    assert rc == 0 and "would apply" in out and "success" in out
    assert _tree(repo) == before
    assert not (tmp_path / "m.db").exists() and not list((tmp_path / "out").glob("*.md"))


def test_default_verifies_learns_and_writes_pr_with_the_applied_diff(tmp_path, capsys):
    repo = _repo(tmp_path)
    before = _tree(repo)
    db = tmp_path / "shared.db"
    rc = main(["scan", str(repo), "--db", str(db), "--explore", "--pr", str(tmp_path / "out")])
    assert rc == 0
    (draft,) = (tmp_path / "out").glob("*_BOLA_show_order.md")
    body = draft.read_text()
    assert "## exploit-verified fix · BOLA · ownership guard" in body
    assert "+    if order is not None and order[\"user_id\"] != current_user_id():" in body
    assert _tree(repo) == before                              # PR only, no in-place write
    c = sqlite3.connect(db)
    assert c.execute("SELECT status FROM outcomes").fetchall() == [("success",)]


def test_apply_writes_the_verified_fix_and_a_rescan_is_clean(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["scan", str(repo), "--db", str(tmp_path / "m.db"), "--apply"]) == 0
    views = (repo / "shop" / "views.py").read_text()
    assert "current_user_id()" in views and "from shop.auth import current_user_id" in views
    assert main(["scan", str(repo), "--detect-only"]) == 0     # nothing left to find
