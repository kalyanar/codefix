"""M5 baselines: run Bandit, Semgrep, CodeQL and Pysa over the corpus, save their
raw output, and classify every real finding.

Nothing here is a hard-coded result. The "cross-function authz" columns are
computed by `classify()` from the tools' own output files under
`bench/baselines/raw/`.

Usage
-----
    python bench/baselines.py run    [--tools bandit,semgrep,codeql,pysa] [--targets a,b]
    python bench/baselines.py report                  # raw/ -> baseline_results.json + RESULTS_*.md
    python bench/baselines.py all                     # run, then report

Tool discovery (a tool that cannot run is recorded as skipped, with the reason):
    bandit, semgrep, pyre      on PATH, or in $BASELINE_VENV/bin
    codeql                     $CODEQL, or on PATH; extra query packs from $CODEQL_PACKS
    Pysa app dependencies      $PYSA_DEPS/<target>/ (a site-packages dir put on search_path)

Pysa's analysis binary ships for x86-64 only, so `bench/repro/pysa.sh` runs it in a
linux/amd64 container (qemu on an aarch64 host); `bench/repro/codeql.sh` does the
same for CodeQL. Raw output is stored per platform: raw/<tool>/<platform>/.

Corpus (paper, "Corpus"): every in-process fixture under bench/apps/ (only the app
source, not the exploit/legit/contract harness files), OWASP VAmPI
(bench/apps/vampi/vendor) and the crAPI Python workshop service
(bench/apps/crapi/vendor). pygoat is vendored but NOT scanned:
the paper's corpus table lists it as weak-fit, outside the active corpus.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent            # bench/
ROOT = HERE.parent
APPS = HERE / "apps"
BASE = HERE / "baselines"
RAW = BASE / "raw"
QUERY = BASE / "codeql" / "BolaBarrierGuard.ql"
PYSA_TOY = BASE / "pysa_ws"

TOOLS = ("bandit", "semgrep", "codeql", "pysa")
RECORD_PLATFORM = "linux-x86_64"     # bench/repro images are pinned to linux/amd64

CODEQL_SUITE = "codeql/python-queries:codeql-suites/python-security-extended.qls"
# Semgrep's --config=auto, with no project context, serves the same rule set as
# p/default (checked 2026-09-15: identical bytes, identical findings on VAmPI).
# --config=auto refuses --metrics=off and re-fetches every run, so the pack is
# fetched once per run into scratch, hashed, and the scan runs offline on that file.
# The rules are not vendored (Semgrep Rules License); the sha256 is recorded.
SEMGREP_PACK_URL = "https://semgrep.dev/c/p/default"

# --------------------------------------------------------------------------- corpus

FIXTURES = [
    "admin_bfla", "bfla_decorated", "library_bola", "library_bola_fastapi",
    "library_flat_bola", "mass_assign", "missing_auth", "new_issue_idor_note",
    "shop_bola", "ssrf_preview",
]
HARNESS_FILE = re.compile(r"^(exploit|legit|bypass|contract|run_)\w*\.py$")
EXCLUDED = {
    "pygoat": "weak-fit in the paper's corpus table (client-trust access lab); not in the active corpus",
}


def corpus() -> list[dict]:
    out = []
    for name in FIXTURES:
        d = APPS / name
        files = sorted(p.relative_to(d) for p in d.rglob("*.py")
                       if not HARNESS_FILE.match(p.name) and "__pycache__" not in p.parts)
        out.append({"name": name, "kind": "fixture", "src": d, "files": [str(f) for f in files],
                    "labels": _labels(d)})
    out.append({"name": "vampi", "kind": "real", "src": APPS / "vampi" / "vendor", "files": None,
                "labels": _labels(APPS / "vampi")})
    out.append({"name": "crapi", "kind": "real",
                "src": APPS / "crapi" / "vendor", "files": None,
                "labels": _labels(APPS / "crapi")})
    return out


# crAPI's label.json names an endpoint, not a function. Resolved by reading
# crapi/shop/urls.py: `orders/(?P<order_id>\d+)$` -> OrderControlView (GET -> .get).
ENDPOINT_FUNCTIONS = {
    "GET /workshop/api/shop/orders/<id>": ("crapi/shop/views.py", "OrderControlView.get"),
}


def _labels(d: Path) -> list[dict]:
    p = d / "label.json"
    if not p.exists():
        return []
    out = []
    for x in json.loads(p.read_text()).get("defects", []):
        lab = {"issue_class": x.get("issue_class"), "function": x.get("function"),
               "endpoint": x.get("endpoint")}
        if not lab["function"] and lab["endpoint"] in ENDPOINT_FUNCTIONS:
            lab["path"], lab["function"] = ENDPOINT_FUNCTIONS[lab["endpoint"]]
        out.append(lab)
    return out


def label_spans(t: dict) -> list[dict]:
    """Source location (path, first/last line) of each labelled defect's function."""
    import ast
    files = t["files"] if t["files"] is not None else sorted(
        str(p.relative_to(t["src"])) for p in t["src"].rglob("*.py"))
    spans = []
    for lab in t["labels"]:
        fn = lab.get("function")
        if not fn:
            continue
        for rel in files:
            if lab.get("path") and rel != lab["path"]:
                continue
            try:
                import warnings
                with warnings.catch_warnings():       # vendored code has invalid escape sequences
                    warnings.simplefilter("ignore", SyntaxWarning)
                    tree = ast.parse((t["src"] / rel).read_text(), filename=rel)
            except (SyntaxError, UnicodeDecodeError):
                continue
            for qual, node in _defs(tree):
                if qual == fn or qual.split(".")[-1] == fn:
                    spans.append({**lab, "qualname": qual, "path": rel,
                                  "start": node.lineno, "end": node.end_lineno})
    return spans


def _defs(tree, prefix=""):
    import ast
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            qual = f"{prefix}{node.name}"
            if not isinstance(node, ast.ClassDef):
                yield qual, node
            yield from _defs(node, qual + ".")


def stage(t: dict, root: Path) -> Path:
    """Copy a target's source into a neutral directory named after the target.

    Semgrep's default .semgrepignore skips every path under `vendor/`, and its
    git-aware file discovery depends on where the tree sits. Scanning a staged copy
    gives every tool the same file set, with paths relative to the app root."""
    dst = root / t["name"]
    if dst.exists():
        shutil.rmtree(dst)
    if t["files"] is None:
        shutil.copytree(t["src"], dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    else:
        for f in t["files"]:
            (dst / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(t["src"] / f, dst / f)
    return dst


# --------------------------------------------------------------------------- helpers

def platform_tag() -> str:
    return f"{platform.system().lower()}-{platform.machine().lower()}"


def _find(name: str) -> str | None:
    venv = os.environ.get("BASELINE_VENV")
    if venv and (Path(venv) / "bin" / name).exists():
        return str(Path(venv) / "bin" / name)
    return shutil.which(name)


def _run(cmd, cwd=None, timeout=4 * 3600):
    return subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)


def _first_line(s: str) -> str:
    return next((line.strip() for line in s.splitlines() if line.strip()), "")


def _tool_dir(raw: Path, tool: str) -> Path:
    d = raw / tool / platform_tag()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_meta(d: Path, meta: dict):
    meta = {**meta, "platform": platform_tag(),
            "host_note": os.environ.get("CODEFIX_HOST_NOTE", ""),
            "run_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")}
    (d / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")


# --------------------------------------------------------------------------- tool runners

def run_bandit(targets, staged, raw, scratch):
    exe = _find("bandit")
    if not exe:
        return {"skipped": "bandit not found"}
    d = _tool_dir(raw, "bandit")
    version = _first_line(_run([exe, "--version"]).stdout)
    for t in targets:
        out = d / f"{t['name']}.json"
        out.unlink(missing_ok=True)
        p = _run([exe, "-r", ".", "-f", "json", "-o", out], cwd=staged[t["name"]])
        if not out.exists():
            raise RuntimeError(f"bandit failed on {t['name']}: {p.stderr[-800:]}")
        data = json.loads(out.read_text())
        data.pop("generated_at", None)
        out.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    _write_meta(d, {"tool": "bandit", "version": version,
                    "command": "bandit -r . -f json -o <target>.json   (cwd = staged app root)"})
    return {"version": version}


def _semgrep_rules(scratch: Path, override: str | None):
    if override:
        return override, {"config": override}
    dst = scratch / "semgrep-rules" / "p-default.yaml"
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(SEMGREP_PACK_URL, headers={"User-Agent": "codefix-baselines"})
        with urllib.request.urlopen(req, timeout=300) as r:
            dst.write_bytes(r.read())
    body = dst.read_bytes()
    return str(dst), {"config": SEMGREP_PACK_URL, "config_sha256": hashlib.sha256(body).hexdigest(),
                      "config_rules": len(re.findall(rb"^- id: ", body, flags=re.M)),
                      "equivalent_to": "--config=auto (no project context)"}


def run_semgrep(targets, staged, raw, scratch, override=None):
    exe = _find("semgrep")
    if not exe:
        return {"skipped": "semgrep not found"}
    d = _tool_dir(raw, "semgrep")
    version = _first_line(_run([exe, "--version"]).stdout)
    cfg, cfg_meta = _semgrep_rules(scratch, override)
    for t in targets:
        out = d / f"{t['name']}.json"
        out.unlink(missing_ok=True)
        cmd = [exe, "scan", "--config", cfg, "--json", "-o", out, "--disable-version-check", "."]
        if cfg != "auto":
            cmd.insert(2, "--metrics=off")
        p = _run(cmd, cwd=staged[t["name"]])
        if not out.exists():
            raise RuntimeError(f"semgrep failed on {t['name']}: {p.stderr[-800:]}")
        data = json.loads(out.read_text())
        # rule ids from a local config file carry its directory as a dotted prefix
        prefix = str(Path(cfg).resolve().parent).lstrip("/").replace("/", ".") + "."
        for r in data.get("results", []):
            if r["check_id"].startswith(prefix):
                r["check_id"] = r["check_id"][len(prefix):]
        data.pop("time", None)
        out.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    _write_meta(d, {"tool": "semgrep", "version": version, **cfg_meta,
                    "command": "semgrep scan --metrics=off --config <p/default snapshot> --json .  "
                               "(cwd = staged app root)"})
    return {"version": version}


def run_codeql(targets, staged, raw, scratch):
    exe = os.environ.get("CODEQL") or shutil.which("codeql")
    if not exe:
        return {"skipped": "codeql not found (set $CODEQL)"}
    packs = os.environ.get("CODEQL_PACKS")
    extra = [f"--additional-packs={packs}"] if packs else []
    d = _tool_dir(raw, "codeql")
    version = _first_line(_run([exe, "version"]).stdout)
    try:
        qp = json.loads(_run([exe, "resolve", "qlpacks", *extra, "--format=json"]).stdout)
        pyq = sorted({Path(p).name for p in qp.get("codeql/python-queries", [])})
        pya = sorted({Path(p).name for p in qp.get("codeql/python-all", [])})
    except json.JSONDecodeError:
        pyq, pya = [], []
    for t in targets:
        db = scratch / "codeql-db" / t["name"]
        db.parent.mkdir(parents=True, exist_ok=True)
        p = _run([exe, "database", "create", db, "--language=python",
                  f"--source-root={staged[t['name']]}", "--overwrite", "--threads=0"])
        if p.returncode != 0:
            raise RuntimeError(f"codeql database create failed on {t['name']}: {p.stderr[-1500:]}")
        for suffix, query in (("", CODEQL_SUITE), (".bola", str(QUERY))):
            out = d / f"{t['name']}{suffix}.sarif"
            p = _run([exe, "database", "analyze", db, query, *extra, "--format=sarif-latest",
                      f"--output={out}", "--threads=0", "--rerun"])
            if p.returncode != 0:
                raise RuntimeError(f"codeql analyze {query} failed on {t['name']}: {p.stderr[-1500:]}")
            _normalise_sarif(out)
    _write_meta(d, {"tool": "codeql", "version": version, "python_queries": pyq, "python_all": pya,
                    "suite": CODEQL_SUITE, "extra_query": str(QUERY.relative_to(ROOT)),
                    "command": "codeql database create --language=python; database analyze <suite>; "
                               "database analyze bench/baselines/codeql/BolaBarrierGuard.ql"})
    return {"version": version}


def _normalise_sarif(path: Path):
    """Drop run-specific noise (invocation timestamps, absolute paths) so reruns diff cleanly."""
    data = json.loads(path.read_text())
    for run in data.get("runs", []):
        run.pop("invocations", None)
        run.pop("originalUriBaseIds", None)
        run.pop("automationDetails", None)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


def _pyre_paths():
    exe = _find("pyre")
    if not exe:
        return None, "pyre (pyre-check) not found"
    lib = next((c for c in (Path(exe).resolve().parent.parent / "lib" / "pyre_check",
                            Path(sys.prefix) / "lib" / "pyre_check") if (c / "typeshed").exists()), None)
    if lib is None:
        return None, "pyre_check typeshed/taint models not found"
    binary = Path(exe).parent / "pyre.bin"
    try:
        subprocess.run([str(binary), "-version"], capture_output=True, timeout=300)
    except OSError as e:
        return None, (f"pyre.bin cannot execute on {platform_tag()} ({e.strerror}); "
                      "run bench/repro/pysa.sh (linux/amd64 container)")
    return {"pyre": exe, "lib": lib}, None


def _pyre_version(exe: str) -> str:
    p = _run([exe, "--version"])
    m = re.search(r"Client version:\s*(\S+)", p.stdout + p.stderr)
    return f"pyre-check {m.group(1)}" if m else _first_line(p.stdout + p.stderr)


def _pysa_one(name, workdir: Path, models: list[str], search_path: list[str], paths, d: Path,
              modules: set[str], no_verify: bool = False):
    cfg = {"source_directories": ["."], "taint_models_path": models,
           "typeshed": str(paths["lib"] / "typeshed"), "search_path": search_path}
    (workdir / ".pyre_configuration").write_text(json.dumps(cfg, indent=1))
    out = d / name
    if out.exists():
        shutil.rmtree(out)
    res_dir = workdir.parent / f".pysa-results-{name}"
    cmd = [paths["pyre"], "--noninteractive", "analyze", "--save-results-to", res_dir]
    if no_verify:
        cmd.append("--no-verify")
    p = _run(cmd, cwd=workdir)
    out.mkdir(parents=True)
    (out / "analyze.log").write_text(_tail_log(p.stdout + p.stderr))
    if not (res_dir / "errors.json").exists():
        raise RuntimeError(f"pysa failed on {name}: {(p.stdout + p.stderr)[-2000:]}")
    for f in ("errors.json", "taint-metadata.json"):
        shutil.copy2(res_dir / f, out / f)
    # callables Pysa analysed (call-graph entries + non-stub models), kept for the app's own modules
    callables = set()
    with open(res_dir / "call-graph.json") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("kind") == "call_graph":
                callables.add(rec["data"]["callable"])
    with open(res_dir / "taint-output.json") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("kind") == "model" and rec["data"].get("filename", "*") != "*":
                callables.add(rec["data"]["callable"])
    callables = {c for c in callables if any(c == m or c.startswith(m + ".") for m in modules)}
    (out / "callables.json").write_text(json.dumps(sorted(callables), indent=1) + "\n")
    lib = str(paths["lib"])
    deps = os.environ.get("PYSA_DEPS") or "\0"
    cfg.update(typeshed="<pyre_check>/typeshed",
               taint_models_path=[m.replace(lib, "<pyre_check>") for m in models],
               search_path=[s.replace(deps, "$PYSA_DEPS") for s in search_path])
    (out / "pyre_configuration.json").write_text(json.dumps(cfg, indent=1) + "\n")
    shutil.rmtree(res_dir)


def _tail_log(s: str) -> str:
    s = re.sub(r"^\S+ \S+ \[PID \d+\] ", "", s, flags=re.M)   # drop timestamps
    keep = [line for line in s.splitlines() if re.search(
        r"(Found \d+ issue|Analysis fixpoint started|Iteration #\d+\. \d+ callables|ERROR|WARNING|"
        r"Analyze:|Verified|unresolved|Invalid model|Parsed)", line)]
    return "\n".join(line[:400] for line in keep[-80:]) + "\n"


def run_pysa(targets, staged, raw, scratch):
    paths, why = _pyre_paths()
    if paths is None:
        return {"skipped": why}
    d = _tool_dir(raw, "pysa")
    version = _pyre_version(paths["pyre"])
    shipped = [str(paths["lib"] / m) for m in ("taint", "third_party_taint") if (paths["lib"] / m).exists()]
    deps_root = os.environ.get("PYSA_DEPS")
    deps_used = {}
    for t in targets:
        sp = [str(Path(deps_root) / t["name"])] if deps_root and (Path(deps_root) / t["name"]).is_dir() else []
        deps_used[t["name"]] = bool(sp)
        print(f"  pysa: {t['name']} ...", flush=True)
        # The shipped model set covers many third-party libraries a given app does not
        # install; pyre refuses to start on those unresolved models unless --no-verify.
        _pysa_one(t["name"], staged[t["name"]], shipped, sp, paths, d, _app_modules(t), no_verify=True)
    # the paper's toy workspace, with its hand-written source/sink models
    toy = scratch / "pysa_toy"
    if toy.exists():
        shutil.rmtree(toy)
    shutil.copytree(PYSA_TOY, toy)
    print("  pysa: pysa_toy ...", flush=True)
    _pysa_one("pysa_toy", toy, ["."], [], paths, d, {"target"})
    _write_meta(d, {"tool": "pysa", "version": version,
                    "models_corpus": [m.replace(str(paths["lib"]), "<pyre_check>") for m in shipped],
                    "models_toy": "bench/baselines/pysa_ws/{models.pysa,taint.config}",
                    "app_dependencies_on_search_path": deps_used,
                    "command": "pyre --noninteractive analyze --save-results-to <dir> "
                               "(--no-verify for the corpus runs with shipped models)"})
    return {"version": version}


# --------------------------------------------------------------------------- parsing

def parse(kind: str, d: Path, target: str) -> list[dict] | None:
    """Raw tool output -> normalised findings {rule, name, cwes, path, line, ...}."""
    if kind == "bandit":
        p = d / f"{target}.json"
        if not p.exists():
            return None
        return [{"rule": r["test_id"], "name": r["test_name"],
                 "cwes": [r["issue_cwe"]["id"]] if r.get("issue_cwe") else [],
                 "path": r["filename"].removeprefix("./"), "line": r["line_number"]}
                for r in json.loads(p.read_text())["results"]]
    if kind == "semgrep":
        p = d / f"{target}.json"
        if not p.exists():
            return None
        out = []
        for r in json.loads(p.read_text())["results"]:
            cwe = r["extra"].get("metadata", {}).get("cwe", [])
            cwe = [cwe] if isinstance(cwe, str) else cwe
            out.append({"rule": r["check_id"], "name": r["check_id"].split(".")[-1],
                        "cwes": _cwe_ints(" ".join(cwe)), "path": r["path"].removeprefix("./"),
                        "line": r["start"]["line"]})
        return out
    if kind in ("codeql", "codeql-bola"):
        p = d / (f"{target}.sarif" if kind == "codeql" else f"{target}.bola.sarif")
        if not p.exists():
            return None
        out = []
        for run in json.loads(p.read_text())["runs"]:
            rules = {}
            for comp in [run["tool"]["driver"], *run["tool"].get("extensions", [])]:
                for rule in comp.get("rules", []) or []:
                    rules[rule["id"]] = rule
            for r in run.get("results", []):
                rule = rules.get(r["ruleId"], {})
                loc = r["locations"][0]["physicalLocation"]
                out.append({"rule": r["ruleId"], "name": rule.get("name", r["ruleId"]),
                            "cwes": _cwe_ints(" ".join(rule.get("properties", {}).get("tags", []))),
                            "path": loc["artifactLocation"]["uri"],
                            "line": loc.get("region", {}).get("startLine"),
                            "message": r["message"]["text"]})
        return out
    if kind == "pysa":
        p = d / target / "errors.json"
        if not p.exists():
            return None
        return [{"rule": str(e["code"]), "name": e["name"], "cwes": [], "path": e["path"],
                 "line": e["line"], "callable": e.get("define"), "message": e.get("description")}
                for e in json.loads(p.read_text())]
    raise ValueError(kind)


def _cwe_ints(s: str) -> list[int]:
    return sorted({int(x) for x in re.findall(r"(?i)cwe[-_ /:]*0*(\d+)", s)})


# --------------------------------------------------------------------------- classifier

# The five codefix classes (paper abstract): BOLA, BFLA, missing authentication,
# SSRF, mass assignment. A finding lands in the "cross-function authz" column if its
# CWE or its rule id/name places it in one of them. Deterministic; raw output only.
AUTHZ_CWE = {
    284: "access control", 285: "authorization", 639: "BOLA/IDOR", 862: "missing authorization",
    863: "incorrect authorization", 306: "missing authentication", 915: "mass assignment",
    918: "SSRF",
}
BOLA_BFLA_CWE = {284, 285, 639, 862, 863}
AUTHZ_KEYWORDS = [   # matched against rule id + rule name only, never free-text messages
    (r"\b(bola|bfla|idor)\b", "BOLA/IDOR"),
    (r"insecure[-_ ]direct[-_ ]object", "BOLA/IDOR"),
    (r"authori[sz]", "authorization"),
    (r"access[-_ ]control", "access control"),
    (r"ownership", "BOLA/IDOR"),
    (r"missing[-_ ](authentication|authn|auth)\b", "missing authentication"),
    (r"mass[-_ ]assign", "mass assignment"),
    (r"\bssrf\b|server[-_ ]side[-_ ]request", "SSRF"),
]
BOLA_BFLA_CLASSES = {"BOLA/IDOR", "authorization", "access control", "missing authorization",
                     "incorrect authorization"}


def classify(f: dict) -> dict:
    hits = [c for c in f["cwes"] if c in AUTHZ_CWE]
    if hits:
        return {"authz": True, "class": AUTHZ_CWE[hits[0]], "basis": f"CWE-{hits[0]}",
                "bola_bfla": any(c in BOLA_BFLA_CWE for c in hits)}
    text = f"{f['rule']} {f.get('name', '')}".lower().replace(".", " ")
    for pat, cls in AUTHZ_KEYWORDS:
        if re.search(pat, text):
            return {"authz": True, "class": cls, "basis": f"rule-id keyword /{pat}/",
                    "bola_bfla": cls in BOLA_BFLA_CLASSES}
    return {"authz": False, "class": None, "basis": None, "bola_bfla": False}


# --------------------------------------------------------------------------- codefix hook

def codefix_authz(target_dir) -> int:
    """codefix's own cross-function authz finding count for an app directory:
    one CodeMap over the whole tree (reproducers and tests excluded), all five
    built-in detectors. Returns -1 if codefix cannot be imported."""
    try:
        src = str(ROOT / "src")
        if src not in sys.path:
            sys.path.insert(0, src)
        import warnings
        from codefix import detect, graph
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            return len(detect.detect_all(graph.build(str(target_dir),
                                                     exclude=graph.harness_excluder)))
    except Exception:  # noqa: BLE001  ImportError, API mismatch, engine errors on real apps
        return -1


# --------------------------------------------------------------------------- report

def _variants(raw: Path, tool: str) -> list[Path]:
    base = raw / tool
    if not base.exists():
        return []
    vs = [p for p in base.iterdir() if (p / "meta.json").exists()]
    # the pinned repro platform is the output of record wherever the report is generated
    return sorted(vs, key=lambda p: (p.name != RECORD_PLATFORM, p.name))


def _fset(fs):
    return sorted((f["rule"], f["path"], f["line"]) for f in fs or [])


def collect(raw: Path, targets: list[dict]) -> dict:
    res = {"tools": {}, "rows": [], "excluded": EXCLUDED}
    toy = {"name": "pysa_toy", "kind": "toy", "src": PYSA_TOY, "files": ["target.py"],
           "labels": [{"issue_class": "BOLA", "function": "get_order", "endpoint": None}]}
    for t in targets + [toy]:
        t["spans"] = label_spans(t)
    for tool in TOOLS:
        vs = _variants(raw, tool)
        if not vs:
            res["tools"][tool] = {"ran": False}
            continue
        prim = vs[0]
        kinds = [tool] + (["codeql-bola"] if tool == "codeql" else [])
        tlist = targets + ([toy] if tool == "pysa" else [])
        cross = {}
        for v in vs[1:]:
            compared, same = 0, True
            for kind in kinds:
                for t in tlist:
                    a, b = parse(kind, prim, t["name"]), parse(kind, v, t["name"])
                    if a is not None and b is not None:
                        compared += 1
                        same = same and _fset(a) == _fset(b)
            cross[v.name] = {"identical_findings": same, "compared": compared,
                             "version": json.loads((v / "meta.json").read_text()).get("version")}
        res["tools"][tool] = {"ran": True, "primary": prim.name,
                              "meta": json.loads((prim / "meta.json").read_text()),
                              "cross_platform": cross}
        for kind in kinds:
            for t in tlist:
                fs = parse(kind, prim, t["name"])
                if fs is None:
                    continue
                for f in fs:
                    f.update(classify(f))
                for f in fs:
                    f["in_labelled_function"] = _label_match(t, f).startswith("**yes")
                row = {"tool": kind, "target": t["name"], "kind": t["kind"], "total": len(fs),
                       "authz": sum(f["authz"] for f in fs), "bola_bfla": sum(f["bola_bfla"] for f in fs),
                       "labelled_defects": len(t["spans"]),
                       "labelled_defects_with_any_finding": sorted({
                           s["qualname"] for s in t["spans"] for f in fs
                           if f["path"] == s["path"] and f["line"] and s["start"] <= f["line"] <= s["end"]}),
                       "findings": fs}
                if tool == "pysa":
                    cp = prim / t["name"] / "callables.json"
                    callables = json.loads(cp.read_text()) if cp.exists() else []
                    # count only callables defined in the target's own modules, not its libraries
                    mods = _app_modules(t)
                    row["n_callables"] = sum(1 for c in callables
                                             if any(c == m or c.startswith(m + ".") for m in mods))
                    row["analysed_label_functions"] = {
                        f"{s['path']}:{s['qualname']}": [c for c in callables if c == _pysa_name(s)]
                        for s in t["spans"]}
                res["rows"].append(row)
    return res


def _app_modules(t) -> set[str]:
    files = t["files"] if t["files"] is not None else [
        str(p.relative_to(t["src"])) for p in t["src"].rglob("*.py")]
    return {f[:-3].replace("/", ".").removesuffix(".__init__") for f in files}


def _pysa_name(span) -> str:
    mod = span["path"][:-3].replace("/", ".").removesuffix(".__init__")
    return f"{mod}.{span['qualname']}"


def write_report(res: dict, targets: list[dict]):
    out = {"generated_by": "python bench/baselines.py report",
           "classifier": {"authz_cwes": AUTHZ_CWE, "rule_id_keywords": [p for p, _ in AUTHZ_KEYWORDS]},
           "excluded_targets": res["excluded"], "tools": res["tools"],
           "codefix_authz": res.get("codefix", {}), "rows": []}
    for r in res["rows"]:
        slim = {k: v for k, v in r.items() if k != "findings"}
        slim["rules"] = _rule_counts(r["findings"])
        slim["authz_findings"] = [f for f in r["findings"] if f["authz"]]
        out["rows"].append(slim)
    (HERE / "baseline_results.json").write_text(json.dumps(out, indent=2) + "\n")
    (HERE / "RESULTS_baselines.md").write_text(_md_main(res, targets))
    (BASE / "RESULTS_pysa_codeql.md").write_text(_md_pysa_codeql(res, targets))


def _rule_counts(fs):
    c = {}
    for f in fs:
        c[f["rule"]] = c.get(f["rule"], 0) + 1
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))


def _row(res, kind, target):
    return next((r for r in res["rows"] if r["tool"] == kind and r["target"] == target), None)


def _fmt_rules(fs, limit=10):
    parts = [f"`{k}`" + (f" x{v}" if v > 1 else "") for k, v in _rule_counts(fs).items()]
    if not parts:
        return "none"
    more = len(parts) - limit
    return ", ".join(parts[:limit]) + (f", +{more} more rules" if more > 0 else "")


KINDS = ["bandit", "semgrep", "codeql", "codeql-bola", "pysa"]
KIND_LABEL = {"bandit": "Bandit", "semgrep": "Semgrep", "codeql": "CodeQL suite",
              "codeql-bola": "CodeQL BarrierGuard query", "pysa": "Pysa"}
PAPER_VERSION = {"bandit": "1.9.4", "semgrep": "1.166.0", "codeql": "(not stated)",
                 "pysa": "pyre-check (not stated)"}


def _versions_md(res):
    lines = ["| Tool | Measured version | Paper | Raw output of record | Other platforms |",
             "|---|---|---|---|---|"]
    for tool in TOOLS:
        info = res["tools"][tool]
        if not info.get("ran"):
            lines.append(f"| {tool} | not run | {PAPER_VERSION[tool]} | - | - |")
            continue
        m = info["meta"]
        v = m.get("version", "?")
        if tool == "codeql":
            v += f"; python-queries {'/'.join(m.get('python_queries') or ['?'])}"
            v += f", python-all {'/'.join(m.get('python_all') or ['?'])}"
        rec = f"`raw/{tool}/{info['primary']}/`" + (f" ({m['host_note']})" if m.get("host_note") else "")
        cross = "; ".join(
            f"`{k}` ({c['version']}): {'identical findings' if c['identical_findings'] else 'DIFFERENT findings'}"
            f" on {c['compared']} outputs" for k, c in info["cross_platform"].items()) or "-"
        lines.append(f"| {tool} | {v} | {PAPER_VERSION[tool]} | {rec} | {cross} |")
    return "\n".join(lines)


def _label_match(t, f):
    """Does the finding's location fall inside a labelled defect's function?"""
    if not t.get("labels"):
        return "target has no label file"
    for s in t.get("spans", []):
        if f["path"] == s["path"] and f["line"] is not None and s["start"] <= f["line"] <= s["end"]:
            return f"**yes**: {s['issue_class']} `{s['qualname']}`"
    return "no"


def _labels_str(t):
    return ", ".join(f"{s['issue_class']} `{s['path']}:{s['qualname']}`" for s in t.get("spans", [])) or "-"


def _md_main(res, targets) -> str:
    names = [t["name"] for t in targets]
    L = ["# M5 baselines: Bandit, Semgrep, CodeQL, Pysa (measured)\n",
         "Generated by `python bench/baselines.py report` from the raw tool output in "
         "`bench/baselines/raw/`. Every number here is computed from that output; nothing is "
         "hard-coded. Pysa and CodeQL details: `bench/baselines/RESULTS_pysa_codeql.md`.\n",
         "## Tools and versions\n", _versions_md(res) + "\n"]
    sm = res["tools"].get("semgrep", {}).get("meta", {})
    if sm.get("config_sha256"):
        L.append(f"Semgrep rules: `{sm['config']}`, {sm['config_rules']} rules, sha256 "
                 f"`{sm['config_sha256']}`. This is the rule set `--config=auto` serves without "
                 "project context. It is fetched at run time and not vendored.\n")
    L += ["## Corpus\n",
          "Fixtures (app source only; the `exploit*`, `legit*`, `bypass`, `contract` harness files are "
          "not scanned): " + ", ".join(f"`{n}`" for n in FIXTURES) + ". Real apps: `vampi` "
          "(`bench/apps/vampi/vendor`, whole repository) and `crapi` "
          "(`bench/apps/crapi/vendor`, the workshop service at crAPI commit b5fc307, Apache-2.0). Not scanned: "
          + "; ".join(f"`{k}`, {v}" for k, v in res["excluded"].items()) + ".\n",
          "## Classifier: how the authz column is computed\n",
          "A finding counts as **cross-function authz** when the tool's own rule metadata puts it in one of "
          "codefix's five classes (BOLA, BFLA, missing authentication, SSRF, mass assignment). Rules, in order:\n",
          "1. Its CWE is one of " + ", ".join(f"{k} ({v})" for k, v in AUTHZ_CWE.items()) + ". CWEs come "
          "from Bandit `issue_cwe`, Semgrep `metadata.cwe` and CodeQL `external/cwe/*` tags.",
          "2. Otherwise, its rule id or rule name matches one of " + ", ".join(f"`{p}`" for p, _ in AUTHZ_KEYWORDS)
          + ". Free-text messages are never matched. Pysa issues carry no CWE, so only this rule applies to them.\n",
          "**BOLA/BFLA** is the stricter subset: CWE 284, 285, 639, 862 or 863, or a BOLA, IDOR, "
          "authorization or access-control rule id.\n",
          "## Per target\n",
          "Each cell is `findings / authz / BOLA-BFLA`; `-` means not run. The codefix column is "
          "`codefix_authz(app_dir)`: one cross-file CodeMap over the target (reproducers and tests "
          "excluded) and all five built-in detectors. On VAmPI and crAPI it includes every labelled "
          "defect, which `bench/live_codefix.py` then fixes and exploit-verifies live; further findings "
          "there have no reproducer and are reported, not verified.\n",
          "| Target | " + " | ".join(KIND_LABEL[k] for k in KINDS) + " | codefix |",
          "|---|" + "---:|" * (len(KINDS) + 1)]
    for n in names:
        cells = []
        for k in KINDS:
            r = _row(res, k, n)
            cells.append("-" if r is None else f"{r['total']} / {r['authz']} / {r['bola_bfla']}")
        L.append(f"| {n} | " + " | ".join(cells) + f" | {res.get('codefix', {}).get(n, -1)} |")
    L += ["", "## Corpus totals\n", "| Tool | Targets | Findings | Cross-function authz | BOLA/BFLA |",
          "|---|---:|---:|---:|---:|"]
    for k in KINDS:
        rs = [r for r in res["rows"] if r["tool"] == k and r["target"] in names]
        if rs:
            L.append(f"| {KIND_LABEL[k]} | {len(rs)} | {sum(r['total'] for r in rs)} | "
                     f"{sum(r['authz'] for r in rs)} | {sum(r['bola_bfla'] for r in rs)} |")
        else:
            L.append(f"| {KIND_LABEL[k]} | 0 | - | - | - |")
    L += ["", "## Labelled defects: what each tool reported inside the defective function\n",
          "Ground truth is each app's `label.json` (function names, or for crAPI the endpoint resolved "
          "through `crapi/shop/urls.py`). A cell lists every finding whose location falls inside that "
          "function, whatever its class; `-` means none.\n",
          "| Target | Labelled defect | " + " | ".join(KIND_LABEL[k] for k in KINDS) + " |",
          "|---|---|" + "---|" * len(KINDS)]
    for t in targets:
        for s in t["spans"]:
            cells = []
            for k in KINDS:
                r = _row(res, k, t["name"])
                if r is None:
                    cells.append("not run")
                    continue
                inside = [f for f in r["findings"] if f["path"] == s["path"] and f["line"]
                          and s["start"] <= f["line"] <= s["end"]]
                cells.append(", ".join(f"`{f['rule'].split('/')[-1]}`:{f['line']}" for f in inside) or "-")
            L.append(f"| {t['name']} | {s['issue_class']} `{s['path']}:{s['qualname']}` | " + " | ".join(cells) + " |")
    L += ["", "## Native classes found (rule id and count)\n"]
    for k in KINDS:
        rs = [r for r in res["rows"] if r["tool"] == k and r["target"] in names]
        if not rs:
            continue
        L.append(f"**{KIND_LABEL[k]}**\n")
        L += [f"- `{r['target']}` ({r['total']}): {_fmt_rules(r['findings'], 14)}" for r in rs if r["total"]]
        empty = [r["target"] for r in rs if not r["total"]]
        if empty:
            L.append(f"- no findings: {', '.join(empty)}")
        L.append("")
    L.append("## Every finding in the authz column\n")
    az = [(r, f) for r in res["rows"] if r["target"] in names for f in r["findings"] if f["authz"]]
    if not az:
        L.append("None.\n")
    else:
        L += ["| Tool | Target | Rule | Location | Class (basis) | Names a labelled defect's function? |",
              "|---|---|---|---|---|---|"]
        for r, f in az:
            t = next(t for t in targets if t["name"] == r["target"])
            L.append(f"| {KIND_LABEL[r['tool']]} | {r['target']} | `{f['rule']}` | `{f['path']}:{f['line']}` | "
                     f"{f['class']} ({f['basis']}) | {_label_match(t, f)} |")
        L.append("")
    L.append(_claims_md(res, names))
    L.append(REPRO_MD)
    return "\n".join(L) + "\n"


def _claims_md(res, names) -> str:
    def rule_n(kind, target, rule):
        r = _row(res, kind, target)
        return "not run" if r is None else str(sum(1 for f in r["findings"] if f["rule"] == rule))

    def rules_like(kind, target, sub):
        r = _row(res, kind, target)
        if r is None:
            return "not run"
        rc = _rule_counts([f for f in r["findings"] if sub.lower() in f["rule"].lower()])
        return ", ".join(f"`{k}` x{v}" for k, v in rc.items()) or "0 matching findings"

    def totals(kind):
        rs = [r for r in res["rows"] if r["tool"] == kind and r["target"] in names]
        if not rs:
            return "not run"
        return (f"**{sum(r['authz'] for r in rs)}** authz-class, **{sum(r['bola_bfla'] for r in rs)}** "
                f"BOLA/BFLA (over {len(rs)} targets, {sum(r['total'] for r in rs)} findings)")

    L = ["## Paper Table III: claimed vs measured\n", "| Claim | Measured |", "|---|---|",
         f"| Bandit, VAmPI: hardcoded passwords B105 x4 | B105 = {rule_n('bandit', 'vampi', 'B105')} |",
         f"| Bandit, VAmPI: bind-all-interfaces B104 | B104 = {rule_n('bandit', 'vampi', 'B104')} |",
         f"| Bandit, VAmPI: SQLi B608 | B608 = {rule_n('bandit', 'vampi', 'B608')} |",
         f"| Bandit, VAmPI: weak RNG B311 | B311 = {rule_n('bandit', 'vampi', 'B311')} |",
         f"| Bandit: 0 cross-function authz | {totals('bandit')} |",
         f"| Semgrep, VAmPI: JWT misuse | {rules_like('semgrep', 'vampi', 'jwt')} |",
         f"| Semgrep, VAmPI: hardcoded SECRET_KEY | {rules_like('semgrep', 'vampi', 'secret_key')} |",
         f"| Semgrep, VAmPI: missing-user entrypoint | {rules_like('semgrep', 'vampi', 'missing-user')} |",
         f"| Semgrep: 0 cross-function authz | {totals('semgrep')} |"]
    toy = _row(res, "pysa", "pysa_toy")
    if toy is None:
        L += ["| Pysa: user-input to eval flow (code 5001) | not run |",
              "| Pysa analyses the BOLA's target function but reports nothing | not run |"]
    else:
        corpus5001 = sum(1 for r in res["rows"] if r["tool"] == "pysa" and r["target"] in names
                         for f in r["findings"] if f["rule"] == "5001")
        where = ", ".join(sorted({f"`{f.get('callable')}`" for f in toy["findings"] if f["rule"] == "5001"}))
        L.append(f"| Pysa: user-input to eval flow (code 5001) | toy workspace `pysa_ws` (hand-written models): "
                 f"{rule_n('pysa', 'pysa_toy', '5001')} in {where or '-'}; corpus with shipped models: "
                 f"{corpus5001} |")
        an = []
        for r in res["rows"]:
            if r["tool"] == "pysa":
                for key, cs in r.get("analysed_label_functions", {}).items():
                    path, qual = key.split(":", 1)
                    inside = [f for f in r["findings"] if f["path"] == path and f.get("callable", "").endswith("." + qual)]
                    what = ("nothing" if not inside else
                            ", ".join(f"{k} {v}x" for k, v in _rule_counts(
                                [{**f, "rule": f"{f['rule']} {f['name']}"} for f in inside]).items())
                            + f" ({sum(f['authz'] for f in inside)} authz)")
                    an.append(f"{r['target']} `{qual}`: {'analysed' if cs else 'not in call graph'}, reports {what}")
        L.append("| Pysa analyses the BOLA's target function but reports nothing | " + "; ".join(an) + " |")
    L += [f"| Pysa: 0 cross-function authz | {totals('pysa')} |",
          f"| CodeQL, VAmPI: py/redos x3 | {rules_like('codeql', 'vampi', 'redos')} |",
          f"| CodeQL: no authz query out of the box, 0 cross-function authz | {totals('codeql')} |",
          f"| Even CodeQL's BarrierGuard finds no BOLA | hand-written BarrierGuard query: {totals('codeql-bola')} |",
          ""]
    return "\n".join(L)


REPRO_MD = """## Reproduce

```bash
# Bandit + Semgrep natively (venv with bandit==1.9.4 semgrep==1.166.0), CodeQL natively if available
BASELINE_VENV=/path/to/venv CODEQL=/path/to/codeql/codeql CODEQL_PACKS=/path/to/packs \\
    python bench/baselines.py run --tools bandit,semgrep,codeql
bench/repro/codeql.sh    # CodeQL in a linux/amd64 container   -> raw/codeql/linux-x86_64/
bench/repro/pysa.sh      # Bandit, Semgrep, Pysa in the linux/amd64 repro image -> raw/*/linux-x86_64/
python bench/baselines.py report
```

On an aarch64 host, register amd64 emulation first. The registration does not survive a reboot:
`docker run --privileged --rm tonistiigi/binfmt --install amd64`.
"""


def _md_pysa_codeql(res, targets) -> str:
    names = [t["name"] for t in targets]
    L = ["# Pysa and CodeQL baselines (measured)\n",
         "Generated by `python bench/baselines.py report` from `bench/baselines/raw/{pysa,codeql}/`. "
         "The classifier and the all-tool tables are in `bench/RESULTS_baselines.md`.\n",
         "## Versions\n", _versions_md(res) + "\n",
         "## CodeQL: standard suite (`python-security-extended.qls`)\n"]
    if not res["tools"]["codeql"].get("ran"):
        L.append("Not run.\n")
    else:
        L += ["| Target | Findings | Rules | Cross-function authz |", "|---|---:|---|---:|"]
        L += [f"| {n} | {r['total']} | {_fmt_rules(r['findings'])} | {r['authz']} |"
              for n in names if (r := _row(res, "codeql", n))]
        L += ["", "## CodeQL: hand-written BarrierGuard BOLA query\n",
              "`bench/baselines/codeql/BolaBarrierGuard.ql` tracks taint from `RemoteFlowSource` (CodeQL's own "
              "model of routed parameters and request data) into the key argument of an object lookup "
              "(`get`, `filter`, `filter_by`, `get_or_404`, `first_or_404`, `exclude`, `get_object_or_404`). "
              "A comparison of the tracked value against an expression that names the principal "
              "(user, owner, identity, token, ...) is a `BarrierGuard`. Lookups already scoped by the principal, "
              "or whose result is later compared with the principal, are not sinks. The query was written once "
              "and not tuned to the corpus.\n",
              "| Target | Hits | Labelled defects | Each hit: function, location, names a labelled function? |",
              "|---|---:|---|---|"]
        for n in names:
            r = _row(res, "codeql-bola", n)
            if r:
                t = next(t for t in targets if t["name"] == n)
                hits = "; ".join(f"{_fn_from_msg(f)} `{f['path']}:{f['line']}` ({_label_match(t, f)})"
                                 for f in r["findings"]) or "-"
                L.append(f"| {n} | {r['total']} | {_labels_str(t)} | {hits} |")
        L += ["", "The fixtures use no web framework, so CodeQL has no `RemoteFlowSource` in them and the query "
              "cannot fire there.\n"]
    L.append("## Pysa\n")
    if not res["tools"]["pysa"].get("ran"):
        L.append("Not run.\n")
    else:
        m = res["tools"]["pysa"]["meta"]
        with_deps = ", ".join(k for k, v in m["app_dependencies_on_search_path"].items() if v) or "none"
        L += [f"Corpus runs use Pysa's shipped models ({', '.join(f'`{x}`' for x in m['models_corpus'])}); "
              f"targets with their own dependencies installed on `search_path`: {with_deps}. `pysa_toy` is "
              "`bench/baselines/pysa_ws`, a 12-line toy with hand-written `models.pysa` and `taint.config`; it is "
              "not part of the corpus. \"Callables analysed\" counts callables from the target's own modules (not its libraries) that "
              "appear in Pysa's call graph or taint models.\n",
              "| Target | Issues | Issue codes | Callables analysed | Labelled function analysed? |",
              "|---|---:|---|---:|---|"]
        for n in names + ["pysa_toy"]:
            r = _row(res, "pysa", n)
            if not r:
                continue
            codes = "; ".join(f"{f['rule']} {f['name']} in `{f.get('callable')}`" for f in r["findings"]) or "-"
            an = "; ".join(f"`{fn}`: " + (", ".join(f"`{c}`" for c in cs) if cs else "no")
                           for fn, cs in r["analysed_label_functions"].items()) or "-"
            L.append(f"| {n} | {r['total']} | {codes} | {r['n_callables']} | {an} |")
        L.append("")
    return "\n".join(L) + "\n"


def _fn_from_msg(f):
    m = re.search(r"in '([^']+)'", f.get("message", ""))
    return f"`{m.group(1)}`" if m else ""


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["run", "report", "all"], nargs="?", default="all")
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--targets", default=None, help="comma-separated subset of target names")
    ap.add_argument("--raw-dir", default=str(RAW))
    ap.add_argument("--scratch", default=None, help="staging and CodeQL db dir (default: fresh temp dir)")
    ap.add_argument("--semgrep-config", default=None, help="override, e.g. 'auto' (needs network + metrics)")
    ap.add_argument("--strict", action="store_true", help="exit 2 if a requested tool cannot run")
    a = ap.parse_args(argv)

    targets = corpus()
    if a.targets:
        want = set(a.targets.split(","))
        targets = [t for t in targets if t["name"] in want]
    raw = Path(a.raw_dir)
    rc = 0
    if a.cmd in ("run", "all"):
        scratch = Path(a.scratch or tempfile.mkdtemp(prefix="codefix-baselines-"))
        runners = {"bandit": run_bandit, "codeql": run_codeql, "pysa": run_pysa,
                   "semgrep": lambda *x: run_semgrep(*x, override=a.semgrep_config)}
        for tool in [t for t in a.tools.split(",") if t]:
            stage_root = scratch / "corpus" / tool      # fresh copy per tool
            stage_root.mkdir(parents=True, exist_ok=True)
            staged = {t["name"]: stage(t, stage_root) for t in targets}
            print(f"[{tool}] {len(targets)} targets on {platform_tag()} ...", flush=True)
            info = runners[tool](targets, staged, raw, scratch)
            print(f"[{tool}] {info}", flush=True)
            if "skipped" in info and a.strict:
                rc = 2
    if a.cmd in ("report", "all"):
        all_targets = corpus()
        res = collect(raw, all_targets)
        cf_root = Path(tempfile.mkdtemp(prefix="codefix-baselines-cf-"))
        res["codefix"] = {t["name"]: codefix_authz(stage(t, cf_root)) for t in all_targets}
        shutil.rmtree(cf_root, ignore_errors=True)
        write_report(res, all_targets)
        print((HERE / "RESULTS_baselines.md").read_text())
    return rc


if __name__ == "__main__":
    sys.exit(main())
