"""PatchMemory — one SQLite file = system of record.

Exact key = (issue_class, sink_shape, topology, framework) UNIQUE.
Posteriors are scoped per (fingerprint, template) and use an informative prior
Beta(alpha0 + successes, beta0 + regressions). `applied_no_tests` is neutral.
(sqlite-vec L5 ANN + L4 bitmask are milestone M9; not in the slice.)
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from .fingerprint import FingerprintKey, embedding, precondition_mask

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY,
    issue_class TEXT, source_role TEXT, sink_category TEXT,
    missing_guard_class TEXT, fix_locus TEXT, framework TEXT,
    embedding TEXT, precond_mask INTEGER,         -- L5/L4 for fuzzy recall (M7)
    UNIQUE(issue_class, source_role, sink_category,
           missing_guard_class, fix_locus, framework)
);
CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE, issue_class TEXT, transform_id TEXT
);
CREATE TABLE IF NOT EXISTS links (
    template_id INTEGER, fingerprint_id INTEGER,
    alpha0 REAL DEFAULT 1.0, beta0 REAL DEFAULT 1.0,
    successes INTEGER DEFAULT 0, regressions INTEGER DEFAULT 0,
    UNIQUE(template_id, fingerprint_id)
);
CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY,
    fingerprint_id INTEGER, template_id INTEGER,
    provenance TEXT, rendered_diff TEXT, applied_at TEXT
);
CREATE TABLE IF NOT EXISTS outcomes (
    id INTEGER PRIMARY KEY,
    patch_id INTEGER, status TEXT, signal_source TEXT
);
CREATE TABLE IF NOT EXISTS detector_specs (
    id INTEGER PRIMARY KEY,
    issue_class TEXT UNIQUE, flow TEXT, transform_id TEXT,
    source_role TEXT, sink_category TEXT, missing_guard_class TEXT, fix_locus TEXT,
    provenance TEXT
);
"""


@dataclass
class TemplateStat:
    template_id: int
    name: str
    transform_id: str
    alpha0: float
    beta0: float
    successes: int
    regressions: int


class PatchMemory:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

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
        row = self.conn.execute(
            "SELECT id FROM fingerprints WHERE issue_class=? AND source_role=?"
            " AND sink_category=? AND missing_guard_class=? AND fix_locus=?"
            " AND framework=?", cols).fetchone()
        return row["id"]

    def fuzzy_lookup(self, key: FingerprintKey, threshold: float = 0.95, embedder=None):
        """On exact-key miss: nearest stored fingerprint of the same class by
        cosine(embedding) + Hamming(precond_mask)<=1. With `embedder` (M9, flagged)
        the similarity uses the *learned* embedding; without it, the deterministic
        M7 embedding. Brute-force NN (sqlite-vec is the scale upgrade)."""
        if embedder is not None:
            from .contrastive import tokenize
            q = embedder.embed(tokenize(key.issue_class, key.sink_category,
                                        key.missing_guard_class, key.framework))
        else:
            q = embedding(key)
        qmask = precondition_mask(key)
        rows = self.conn.execute(
            "SELECT id, sink_category, missing_guard_class, framework, embedding,"
            " precond_mask FROM fingerprints WHERE issue_class=?",
            (key.issue_class,)).fetchall()
        best = None
        for r in rows:
            templates = self.templates_for(r["id"], key.issue_class)
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

    # templates -------------------------------------------------------------
    def seed_template(self, name: str, issue_class: str, transform_id: str) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO templates(name,issue_class,transform_id) VALUES(?,?,?)",
            (name, issue_class, transform_id),
        )
        self.conn.commit()
        return self.conn.execute(
            "SELECT id FROM templates WHERE name=?", (name,)
        ).fetchone()["id"]

    def link(self, template_id: int, fingerprint_id: int, alpha0=1.0, beta0=1.0):
        self.conn.execute(
            "INSERT OR IGNORE INTO links(template_id,fingerprint_id,alpha0,beta0)"
            " VALUES(?,?,?,?)",
            (template_id, fingerprint_id, alpha0, beta0),
        )
        self.conn.commit()

    # detector specs (M13: developer-extensible catalog) -------------------
    def admit_spec(self, spec, provenance: str = "llm-authored"):
        """Persist a gate-passed DetectorSpec into the catalog."""
        self.conn.execute(
            "INSERT OR REPLACE INTO detector_specs(issue_class,flow,transform_id,"
            "source_role,sink_category,missing_guard_class,fix_locus,provenance)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (spec.issue_class, spec.flow, spec.transform_id, spec.source_role,
             spec.sink_category, spec.missing_guard_class, spec.fix_locus, provenance))
        self.conn.commit()

    def load_specs(self):
        """Load admitted DetectorSpecs so the engine runs them — no engine code."""
        from .detect import DetectorSpec
        rows = self.conn.execute(
            "SELECT issue_class,flow,transform_id,source_role,sink_category,"
            "missing_guard_class,fix_locus FROM detector_specs").fetchall()
        return [DetectorSpec(r["issue_class"], r["flow"], r["transform_id"],
                             r["source_role"], r["sink_category"],
                             r["missing_guard_class"], r["fix_locus"]) for r in rows]

    def bucket_stats(self, key: FingerprintKey, exclude_fp_id: int | None = None):
        """Aggregate (successes, regressions) across ALL fingerprints in the same
        framework-independent semantic bucket (issue_class, sink_category,
        missing_guard_class). Excludes `exclude_fp_id` (the current fingerprint)
        so it's a true *prior* from OTHER instances of the pattern. This is what
        lets a new/cold fingerprint borrow strength — the hierarchical prior (M8)."""
        sql = ("SELECT COALESCE(SUM(l.successes),0), COALESCE(SUM(l.regressions),0)"
               " FROM links l JOIN fingerprints f ON f.id=l.fingerprint_id"
               " WHERE f.issue_class=? AND f.sink_category=? AND f.missing_guard_class=?")
        args = [key.issue_class, key.sink_category, key.missing_guard_class]
        if exclude_fp_id is not None:
            sql += " AND f.id != ?"
            args.append(exclude_fp_id)
        r = self.conn.execute(sql, args).fetchone()
        return (r[0], r[1])

    def templates_for(self, fingerprint_id: int, issue_class: str) -> list[TemplateStat]:
        rows = self.conn.execute(
            "SELECT t.id,t.name,t.transform_id,l.alpha0,l.beta0,l.successes,l.regressions"
            " FROM templates t JOIN links l ON l.template_id=t.id"
            " WHERE l.fingerprint_id=? AND t.issue_class=?",
            (fingerprint_id, issue_class),
        ).fetchall()
        return [TemplateStat(r["id"], r["name"], r["transform_id"], r["alpha0"],
                             r["beta0"], r["successes"], r["regressions"]) for r in rows]

    # patches + outcomes ----------------------------------------------------
    def record_patch(self, fingerprint_id, template_id, provenance, diff, ts) -> int:
        cur = self.conn.execute(
            "INSERT INTO patches(fingerprint_id,template_id,provenance,rendered_diff,applied_at)"
            " VALUES(?,?,?,?,?)",
            (fingerprint_id, template_id, provenance, diff, ts),
        )
        self.conn.commit()
        return cur.lastrowid

    def record_outcome(self, patch_id, fingerprint_id, template_id, status, signal_source):
        self.conn.execute(
            "INSERT INTO outcomes(patch_id,status,signal_source) VALUES(?,?,?)",
            (patch_id, status, signal_source),
        )
        if status == "success":
            self.conn.execute(
                "UPDATE links SET successes=successes+1"
                " WHERE template_id=? AND fingerprint_id=?", (template_id, fingerprint_id))
        elif status == "regression":
            self.conn.execute(
                "UPDATE links SET regressions=regressions+1"
                " WHERE template_id=? AND fingerprint_id=?", (template_id, fingerprint_id))
        # 'applied_no_tests' => neutral, no posterior update
        self.conn.commit()
