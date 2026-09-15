"""SCIP index reading (stdlib only) and symbol parsing.

SCIP (https://github.com/sourcegraph/scip) is a protobuf index produced by
language indexers — scip-python, scip-typescript, scip-java, scip-go. This
module decodes the subset codefix needs without a protobuf dependency:

  Index.documents[]            (field 2)
    Document.relative_path     (1)
    Document.occurrences[]     (2)   range (1, packed int32), symbol (2),
                                     symbol_roles (3), enclosing_range (7)
    Document.symbols[]         (3)   symbol (1), kind (5), display_name (6)
    Document.language          (4)
    Document.text              (5)

The symbol-string parser is ported from codefix v1 (providers/scip_symbol.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

ROLE_DEFINITION = 0x1
ROLE_IMPORT = 0x2
ROLE_WRITE = 0x4
ROLE_READ = 0x8


# --- protobuf wire decoding ---------------------------------------------------
def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf: bytes):
    """Yield (field_number, wire_type, value) for a message; length-delimited
    values are returned as bytes."""
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        fno, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            v, i = buf[i:i + 8], i + 8
        elif wt == 2:
            ln, i = _varint(buf, i)
            v, i = buf[i:i + ln], i + ln
        elif wt == 5:
            v, i = buf[i:i + 4], i + 4
        else:
            raise ValueError(f"unsupported wire type {wt}")
        yield fno, wt, v


def _packed_ints(v, wt) -> list[int]:
    if wt == 0:
        return [v]
    out, i = [], 0
    while i < len(v):
        x, i = _varint(v, i)
        out.append(x)
    return out


@dataclass
class Occurrence:
    range: list[int]
    symbol: str
    roles: int
    enclosing_range: list[int] = field(default_factory=list)

    @property
    def start(self) -> tuple[int, int]:
        return self.range[0], self.range[1]

    @property
    def end(self) -> tuple[int, int]:
        if len(self.range) == 3:
            return self.range[0], self.range[2]
        return self.range[2], self.range[3]


@dataclass
class SymbolInfo:
    symbol: str
    kind: int = 0
    display_name: str = ""


@dataclass
class Document:
    relative_path: str
    language: str = ""
    text: str = ""
    occurrences: list[Occurrence] = field(default_factory=list)
    symbols: list[SymbolInfo] = field(default_factory=list)


def _occurrence(buf: bytes) -> Occurrence:
    rng, sym, roles, enc = [], "", 0, []
    for fno, wt, v in _fields(buf):
        if fno == 1:
            rng += _packed_ints(v, wt)
        elif fno == 2:
            sym = v.decode()
        elif fno == 3:
            roles = v
        elif fno == 7:
            enc += _packed_ints(v, wt)
    return Occurrence(rng, sym, roles, enc)


def _symbol_info(buf: bytes) -> SymbolInfo:
    info = SymbolInfo("")
    for fno, wt, v in _fields(buf):
        if fno == 1:
            info.symbol = v.decode()
        elif fno == 5 and wt == 0:
            info.kind = v
        elif fno == 6 and wt == 2:
            info.display_name = v.decode()
    return info


def _document(buf: bytes) -> Document:
    doc = Document("")
    for fno, wt, v in _fields(buf):
        if fno == 1:
            doc.relative_path = v.decode()
        elif fno == 2:
            doc.occurrences.append(_occurrence(v))
        elif fno == 3:
            doc.symbols.append(_symbol_info(v))
        elif fno == 4 and wt == 2:
            doc.language = v.decode()
        elif fno == 5 and wt == 2:
            doc.text = v.decode()
    return doc


def read_index(path: str | Path) -> list[Document]:
    data = Path(path).read_bytes()
    return [_document(v) for fno, wt, v in _fields(data) if fno == 2]


# --- symbol strings (ported from codefix v1) ------------------------------------
@dataclass(frozen=True)
class ParsedSymbol:
    raw: str
    fqname: str
    name: str
    parent_class: str | None
    module: str
    kind: str          # function | method | type | term | parameter | meta | local | unknown


def parse_symbol(symbol: str) -> ParsedSymbol:
    """``scip-typescript npm pkg 1.0.0 src/`repo.ts`/loadOrder().`` ->
    fqname ``src.repo.loadOrder``, kind ``function``."""
    if not symbol:
        return ParsedSymbol(symbol, "", "", None, "", "unknown")
    if symbol.startswith("local "):
        return ParsedSymbol(symbol, symbol, symbol, None, "", "local")
    parts = symbol.split(" ", 4)
    if len(parts) < 5:
        return ParsedSymbol(symbol, symbol, symbol, None, "", "unknown")
    desc = parts[4]
    kind = "unknown"
    if desc.endswith(")."):
        cut = desc.rfind("(")
        body, kind = desc[:cut], "method"
    elif desc.endswith("#"):
        body, kind = desc[:-1], "type"
    elif desc.endswith("."):
        body, kind = desc[:-1], "term"
    elif desc.endswith(":"):
        body, kind = desc[:-1], "meta"
    elif desc.endswith(")") and "(" in desc:
        body, kind = desc[:desc.rfind("(")], "parameter"
    else:
        body = desc
    segs = [s.strip("`") for s in _split_descriptor(body)]
    segs = [s[:-3] if s.endswith((".py", ".ts", ".js", ".go")) else
            s[:-4] if s.endswith((".tsx", ".jsx")) else s for s in segs]
    parent = None
    if "#" in body and kind == "method":
        parent = segs[-2] if len(segs) >= 2 else None
    elif kind == "method":
        kind = "function"
    name = segs[-1] if segs else ""
    module = ".".join(x for x in segs[:-1] if x and x != parent)
    fq = ".".join(x for x in segs if x)
    return ParsedSymbol(symbol, fq, name, parent, module, kind)


def _split_descriptor(body: str) -> list[str]:
    out, cur, tick = [], "", False
    for ch in body:
        if ch == "`":
            tick = not tick
            cur += ch
        elif not tick and ch in "/#.":
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out
