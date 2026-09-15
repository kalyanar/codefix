"""PatchMemory — one SQLite file, the persistent knowledge graph (paper §III.C).

Eight foreign-key-linked tables (schema ported from codefix v1, re-keyed on the
facet fingerprint):

  codebases · fingerprints · issues · templates · template_fingerprint_links ·
  patches · outcomes · detector_specs

Posteriors are per (template, fingerprint): ``alpha = alpha0 + successes`` and
``beta = beta0 + regressions + reverts`` (paper §IV.A). Outcome statuses are
success / regression / reverted / superseded / applied_no_tests; only verified
outcomes move a posterior, and superseded / applied_no_tests are neutral.
Each fingerprint row also carries its framework-independent embedding and
precondition bitmask for fuzzy recall (brute-force nearest neighbour).
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from .fingerprint import FingerprintKey, embedding, precondition_mask

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS codebases (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    language TEXT NOT NULL DEFAULT 'python',
    framework TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY,
    issue_class TEXT NOT NULL, source_role TEXT NOT NULL, sink_category TEXT NOT NULL,
    missing_guard_class TEXT NOT NULL, fix_locus TEXT NOT NULL, framework TEXT NOT NULL,
    embedding TEXT, precond_mask INTEGER,
    UNIQUE(issue_class, source_role, sink_category, missing_guard_class, fix_locus, framework)
);
CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY,
    codebase_id INTEGER NOT NULL REFERENCES codebases(id) ON DELETE CASCADE,
    fingerprint_id INTEGER NOT NULL REFERENCES fingerprints(id),
    issue_class TEXT NOT NULL,
    location TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    UNIQUE(codebase_id, fingerprint_id, location)
);
CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    issue_class TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    params_json TEXT,
    origin TEXT NOT NULL DEFAULT 'authored',     -- authored | promoted_llm | promoted_fuzzy
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS template_fingerprint_links (
    template_id INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    fingerprint_id INTEGER NOT NULL REFERENCES fingerprints(id) ON DELETE CASCADE,
    alpha0 REAL NOT NULL DEFAULT 1.0, beta0 REAL NOT NULL DEFAULT 1.0,
    successes INTEGER NOT NULL DEFAULT 0, regressions INTEGER NOT NULL DEFAULT 0,
    reverts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (template_id, fingerprint_id)
);
CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY,
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    template_id INTEGER REFERENCES templates(id),
    provenance TEXT NOT NULL,                    -- template | fuzzy | llm_cold
    rendered_diff TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outcomes (
    id INTEGER PRIMARY KEY,
    patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN
        ('success','regression','reverted','superseded','applied_no_tests')),
    signal_source TEXT NOT NULL,                 -- exploit | git | ci | human
    detail TEXT,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detector_specs (
    id INTEGER PRIMARY KEY,
    issue_class TEXT UNIQUE, flow TEXT, transform_id TEXT,
    source_role TEXT, sink_category TEXT, missing_guard_class TEXT, fix_locus TEXT,
    provenance TEXT,
    decorator_anchors TEXT, call_anchors TEXT,
    direction TEXT DEFAULT 'both', depth INTEGER DEFAULT 2,
    sink_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_issues_fp ON issues(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_patches_issue ON patches(issue_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_patch ON outcomes(patch_id);
CREATE INDEX IF NOT EXISTS idx_links_fp ON template_fingerprint_links(fingerprint_id);
"""

_SPEC_MIGRATIONS = [
    ("decorator_anchors", "TEXT"), ("call_anchors", "TEXT"),
    ("direction", "TEXT DEFAULT 'both'"), ("depth", "INTEGER DEFAULT 2"),
    ("sink_json", "TEXT"),
]

# §IV.D: a template is "proven" for a fingerprint once its observed success rate
# clears this threshold over a sufficient sample.
TEMPLATE_MIN_SUCCESS_RATE = 0.8


def pac_min_observations(epsilon: float = 0.25, delta: float = 0.1, hypotheses: int = 5) -> int:
    """n_t >= (1/eps)(ln|H_t| + ln(1/delta)) — the sample needed before a template
    that looks good may be trusted at error eps with confidence 1-delta."""
    return math.ceil((math.log(hypotheses) + math.log(1 / delta)) / epsilon)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TemplateStat:
    template_id: int
    name: str
    transform_id: str
    alpha0: float
    beta0: float
    successes: int
    regressions: int          # regressions + reverts (the beta evidence)

    @property
    def n(self) -> int:
        return self.successes + self.regressions


class PatchMemory:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.execute("PRAGMA foreign_keys = ON")
        have = {r["name"] for r in self.conn.execute("PRAGMA table_info(detector_specs)")}
        for col, decl in _SPEC_MIGRATIONS:
            if col not in have:
                self.conn.execute(f"ALTER TABLE detector_specs ADD COLUMN {col} {decl}")
        self.conn.commit()

    def close(self):
        self.conn.close()

    # codebases -------------------------------------------------------------
    def upsert_codebase(self, path: str, language: str = "python", framework: str | None = None) -> int:
        now = _now()
        self.conn.execute(
            "INSERT INTO codebases(path,language,framework,first_seen,last_seen) VALUES(?,?,?,?,?)"
            " ON CONFLICT(path) DO UPDATE SET last_seen=excluded.last_seen,"
            " framework=COALESCE(excluded.framework, framework)",
            (path, language, framework, now, now))
        self.conn.commit()
        return self.conn.execute("SELECT id FROM codebases WHERE path=?", (path,)).fetchone()["id"]

    # fingerprints ----------------------------------------------------------
    def upsert_fingerprint(self, key: FingerprintKey) -> int:
        cols = (key.issue_class, key.source_role, key.sink_category,
                key.missing_guard_class, key.fix_locus, key.framework)
        self.conn.execute(
            "INSERT OR IGNORE INTO fingerprints(issue_class,source_role,sink_category,"
            "missing_guard_class,fix_locus,framework,embedding,precond_mask)"
            " VALUES(?,?,?,?,?,?,?,?)",
            cols + (json.dumps(embedding(key)), precondition_mask(key)))
        self.conn.commit()
        return self.conn.execute(
            "SELECT id FROM fingerprints WHERE issue_class=? AND source_role=?"
            " AND sink_category=? AND missing_guard_class=? AND fix_locus=?"
            " AND framework=?", cols).fetchone()["id"]

    def fuzzy_lookup(self, key: FingerprintKey, threshold: float = 0.95, embedder=None):
        """On exact-key miss: the nearest stored fingerprint of the same class that
        actually carries a template, by cosine(embedding) with Hamming(mask) <= 1."""
        if embedder is not None:
            from .contrastive import tokenize
            q = embedder.embed(tokenize(key.issue_class, key.sink_category,
                                        key.missing_guard_class, key.framework))
        else:
            q = embedding(key)
        qmask = precondition_mask(key)
        rows = self.conn.execute(
            "SELECT id, sink_category, missing_guard_class, framework, embedding, precond_mask"
            " FROM fingerprints WHERE issue_class=?", (key.issue_class,)).fetchall()
        best = None
        for r in rows:
            templates = [t for t in self.templates_for(r["id"], key.issue_class) if t.successes > 0]
            if not templates:
                continue
            if embedder is not None:
                from .contrastive import tokenize
                emb = embedder.embed(tokenize(key.issue_class, r["sink_category"],
                                              r["missing_guard_class"], r["framework"]))
            else:
                emb = json.loads(r["embedding"])
            sim = sum(a * b for a, b in zip(q, emb))
            ham = bin(qmask ^ (r["precond_mask"] or 0)).count("1")
            if sim >= threshold and ham <= 1 and (best is None or sim > best[2]):
                best = (r["id"], templates, sim)
        return best

    # issues ----------------------------------------------------------------
    def record_issue(self, codebase_id: int, fingerprint_id: int, issue_class: str,
                     location: str) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO issues(codebase_id,fingerprint_id,issue_class,location,detected_at)"
            " VALUES(?,?,?,?,?)", (codebase_id, fingerprint_id, issue_class, location, _now()))
        self.conn.commit()
        return self.conn.execute(
            "SELECT id FROM issues WHERE codebase_id=? AND fingerprint_id=? AND location=?",
            (codebase_id, fingerprint_id, location)).fetchone()["id"]

    # templates -------------------------------------------------------------
    def seed_template(self, name: str, issue_class: str, transform_id: str,
                      origin: str = "authored", params: dict | None = None) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO templates(name,issue_class,transform_id,params_json,origin,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (name, issue_class, transform_id, json.dumps(params or {}), origin, _now()))
        self.conn.commit()
        return self.conn.execute("SELECT id FROM templates WHERE name=?", (name,)).fetchone()["id"]

    def link(self, template_id: int, fingerprint_id: int, alpha0=1.0, beta0=1.0):
        self.conn.execute(
            "INSERT OR IGNORE INTO template_fingerprint_links(template_id,fingerprint_id,alpha0,beta0)"
            " VALUES(?,?,?,?)", (template_id, fingerprint_id, alpha0, beta0))
        self.conn.commit()

    def templates_for(self, fingerprint_id: int, issue_class: str) -> list[TemplateStat]:
        rows = self.conn.execute(
            "SELECT t.id,t.name,t.transform_id,l.alpha0,l.beta0,l.successes,"
            " l.regressions + l.reverts AS bad"
            " FROM templates t JOIN template_fingerprint_links l ON l.template_id=t.id"
            " WHERE l.fingerprint_id=? AND t.issue_class=? ORDER BY t.id",
            (fingerprint_id, issue_class)).fetchall()
        return [TemplateStat(r["id"], r["name"], r["transform_id"], r["alpha0"],
                             r["beta0"], r["successes"], r["bad"]) for r in rows]

    def is_proven(self, template_id: int, fingerprint_id: int,
                  min_rate: float = TEMPLATE_MIN_SUCCESS_RATE, min_n: int | None = None) -> bool:
        r = self.conn.execute(
            "SELECT successes, regressions + reverts AS bad FROM template_fingerprint_links"
            " WHERE template_id=? AND fingerprint_id=?", (template_id, fingerprint_id)).fetchone()
        if r is None:
            return False
        n = r["successes"] + r["bad"]
        need = pac_min_observations() if min_n is None else min_n
        return n >= need and r["successes"] / n >= min_rate

    def bucket_stats(self, key: FingerprintKey, exclude_fp_id: int | None = None):
        """(successes, regressions+reverts) pooled over the defect family (same
        class, sink category and missing guard), excluding the current fingerprint —
        the hierarchical prior a cold fingerprint inherits."""
        sql = ("SELECT COALESCE(SUM(l.successes),0), COALESCE(SUM(l.regressions + l.reverts),0)"
               " FROM template_fingerprint_links l JOIN fingerprints f ON f.id=l.fingerprint_id"
               " WHERE f.issue_class=? AND f.sink_category=? AND f.missing_guard_class=?")
        args = [key.issue_class, key.sink_category, key.missing_guard_class]
        if exclude_fp_id is not None:
            sql += " AND f.id != ?"
            args.append(exclude_fp_id)
        r = self.conn.execute(sql, args).fetchone()
        return (r[0], r[1])

    # detector specs (developer-extensible catalog) -------------------------
    def admit_spec(self, spec, provenance: str = "llm-authored"):
        anchors = (json.dumps(sorted(spec.decorator_anchors)) if spec.decorator_anchors is not None else None,
                   json.dumps(sorted(spec.call_anchors)) if spec.call_anchors is not None else None)
        sink = None
        if getattr(spec, "sink", None) is not None:
            s = spec.sink
            sink = json.dumps({"category": s.category,
                               "names": sorted(s.names) if s.names else None,
                               "name_regex": s.name_regex, "receiver_regex": s.receiver_regex,
                               "symbols": sorted(s.symbols) if s.symbols else None, "arg": s.arg})
        self.conn.execute(
            "INSERT OR REPLACE INTO detector_specs(issue_class,flow,transform_id,"
            "source_role,sink_category,missing_guard_class,fix_locus,provenance,"
            "decorator_anchors,call_anchors,direction,depth,sink_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (spec.issue_class, spec.flow, spec.transform_id, spec.source_role,
             spec.sink_category, spec.missing_guard_class, spec.fix_locus, provenance)
            + anchors + (spec.direction, spec.depth, sink))
        self.conn.commit()

    def load_specs(self):
        from .detect import DetectorSpec, SinkMatcher

        def anchors(v):
            return frozenset(json.loads(v)) if v is not None else None

        out = []
        for r in self.conn.execute("SELECT * FROM detector_specs ORDER BY id").fetchall():
            sink = None
            if r["sink_json"]:
                d = json.loads(r["sink_json"])
                sink = SinkMatcher(d["category"],
                                   frozenset(d["names"]) if d.get("names") else None,
                                   d.get("name_regex"), d.get("receiver_regex"),
                                   frozenset(d["symbols"]) if d.get("symbols") else None,
                                   d.get("arg"))
            spec = DetectorSpec(r["issue_class"], r["flow"], r["transform_id"],
                                r["source_role"], r["sink_category"],
                                r["missing_guard_class"], r["fix_locus"],
                                anchors(r["decorator_anchors"]), anchors(r["call_anchors"]),
                                r["direction"] or "both",
                                r["depth"] if r["depth"] is not None else 2, sink=sink)
            out.append(spec)
        return out

    # patches + outcomes ----------------------------------------------------
    def record_patch(self, issue_id, template_id, provenance, diff) -> int:
        cur = self.conn.execute(
            "INSERT INTO patches(issue_id,template_id,provenance,rendered_diff,applied_at)"
            " VALUES(?,?,?,?,?)", (issue_id, template_id, provenance, diff, _now()))
        self.conn.commit()
        return cur.lastrowid

    def _link_of_patch(self, patch_id):
        return self.conn.execute(
            "SELECT p.template_id, i.fingerprint_id FROM patches p JOIN issues i ON i.id=p.issue_id"
            " WHERE p.id=?", (patch_id,)).fetchone()

    def record_outcome(self, patch_id, status, signal_source, detail: str = ""):
        self.conn.execute(
            "INSERT INTO outcomes(patch_id,status,signal_source,detail,recorded_at) VALUES(?,?,?,?,?)",
            (patch_id, status, signal_source, detail, _now()))
        col = {"success": "successes", "regression": "regressions", "reverted": "reverts"}.get(status)
        row = self._link_of_patch(patch_id)
        if col and row and row["template_id"] is not None:
            self.conn.execute(
                f"UPDATE template_fingerprint_links SET {col}={col}+1"
                " WHERE template_id=? AND fingerprint_id=?",
                (row["template_id"], row["fingerprint_id"]))
        self.conn.commit()

    def mark_reverted(self, patch_id, signal_source: str = "git", detail: str = ""):
        """A merged fix later reverted: counts against its template (beta)."""
        self.record_outcome(patch_id, "reverted", signal_source, detail)

    def mark_superseded(self, patch_id, signal_source: str = "git", detail: str = ""):
        """Replaced by a later fix: recorded, posterior-neutral."""
        self.record_outcome(patch_id, "superseded", signal_source, detail)
