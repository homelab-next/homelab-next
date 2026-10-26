#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: product-name-lint
#   kind: check
#   purpose: Fail when a product name appears in the core outside its provider module, beyond the shrinking baseline.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:gates, make:product-names-baseline]
#   invariant: [X-11]
#   inputs: the tracked tree; tools/product_names.yml; tools/product_names.baseline.json; the role table; the base commit's baseline (--base, --ci-base)
#   outputs: one line per violation; --update rewrites the baseline when no product's total rises
#   exit:
#     "0": clean
#     "1": violations (a new name, a baseline entry above what is there, or a baseline that grew since the base)
#     "2": usage error or a bad vocabulary, allowlist, manifest or baseline
#     "100": the lint itself failed (could not measure)
"""The product-name lint (ADR-0027 rule 1; docs/modules.md, "The product-name lint").

A product's name may appear only in its own provider module, in site configuration and in prose:
the core and the feature and core modules name slots, never products, so a swap never needs a
code change.  The lint reads:

* **the vocabulary**: every provider manifest's ``product.name``, ``product.display`` and
  ``product.aliases`` (``examples/modules/*/module.yml``, the public ``modules/*/module.yml``, and
  ``--overlay DIR/lab/modules/*/module.yml``); the products without a provider module yet
  (``tools/product_names.yml`` ``products:``); and the model identifiers of the role table
  (``bindings[].model_id``, ``--roles``);
* **where a name is allowed**: a provider module's directory, for that provider's own product only;
  site configuration (``examples/modules/sites/``, ``examples/private-overlay/``, an overlay's
  ``lab/``); Markdown prose (ADRs and the changelog included); the role table; and the reviewed
  path globs of ``tools/product_names.yml`` ``allow:`` (each with a reason);
* **what is linted** everywhere else, over the tracked and untracked-but-not-ignored files
  (``git ls-files`` under ROOT; a directory walk outside a git work tree): Python string and
  bytes constants as Python reads them (escapes decoded, implicit concatenation joined, f-string
  parts) and identifiers, without comments and docstrings; every key and string value of YAML
  (sets, ordered maps and binaries included) and JSON, except the string value of a prose key
  (``description``, ``title``, ``$comment``, ``summary``, ``reason``, ``why``, ``purpose``,
  ``help``); the lines of every other text file (any suffix, extensionless included; UTF-8,
  UTF-16 or UTF-32 by BOM or byte pattern, else Latin-1), without the comment lines of formats
  known to use ``#`` or ``//``; every file, directory and submodule name; and a symbolic link's
  target text and, for a link into the tree, the target's content under the link's own path.  A
  binary file (a NUL byte, in a suffix not known as text) is skipped whatever its size; a text file
  over 20 MB is an error, never a silent skip.

**Matching** is case-insensitive after compatibility normalisation with combining marks and
invisible format characters removed, with ``-``, ``_``, ``.`` and a space alike between the parts
of a name (or none: ``uptimekuma``), and bounded: no letter or digit on either side, except at a
camel-case, upper-case-run or letter/digit seam (``OpenbaoClient``, ``OPENBAOClient``,
``getOpenbao``, ``openbao2`` count; ``notopenbao`` and ``OPENBAOADDR`` do not).  A file is parsed
only when its letters and digits contain a name's (or it holds an escape), so the prefilter never
skips a file a parse would match in.
It catches the ordinary spellings, not deliberate obfuscation (``"open" + "bao"``, an encoded
string); that is review's job, which is why this file, the vocabulary and the baseline are owned.

**The baseline** (``tools/product_names.baseline.json``) holds the counts per path and product:
a count above it, or a path or product not in it, fails; so does an entry above what is there.
``--update`` rewrites it to what is there, refused when any product's total would rise (so a moved
file keeps its debt, and debt never grows).  ``--base REV`` / ``--ci-base`` (CI) also compare the
committed baseline and vocabulary with the base commit's: no path's count may rise above its count
there (a file git sees as renamed or copied keeps its old path's counts, so a new file never takes
on debt freed elsewhere), and no spelling linted there (a product, an alias, a provider's display
name, a model id) may stop being linted unless ``retired:`` in the vocabulary says why, so neither
file can be loosened by hand.

Usage:
  python tools/product_name_lint.py [ROOT] [--overlay DIR] [--roles FILE] [--json]
                                    [--update | --init] [--base REV | --ci-base]
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import fnmatch
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import tokenize
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import yaml

    from homelabnext.state.store import atomic_write_text
except ImportError as _exc:  # the lint cannot run: "could not measure", never a pass or a fail
    print(f"product_name_lint: cannot import {_exc.name}", file=sys.stderr)
    sys.exit(100)

VOCABULARY = "tools/product_names.yml"
BASELINE = "tools/product_names.baseline.json"
ROLES = "examples/model_roles.json"
#: only used outside a git checkout (``git ls-files`` already leaves out what is ignored)
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
#: paths where a product name belongs: site configuration and prose
ALWAYS_ALLOWED = (
    "examples/modules/sites/**",
    "examples/private-overlay/**",
    "lab/**",
    "*.md",  # fnmatch's * crosses /, so this is every Markdown file
    VOCABULARY,
    BASELINE,
    ROLES,  # the role table is where model ids belong
)
#: YAML/JSON keys whose string value is prose, not configuration
PROSE_KEYS = frozenset(
    {"description", "title", "$comment", "summary", "reason", "why", "purpose", "help"}
)
HASH_COMMENTS = {
    ".sh", ".bash", ".cfg", ".toml", ".ini", ".conf", ".service", ".timer", ".mount", ".socket",
    ".network", ".netdev", ".nft", ".tf", ".txt", ".env", ".yml", ".yaml", ".j2", ".rules",
    "makefile", "dockerfile", "containerfile", ".gitignore", ".dockerignore", ".gitattributes",
}  # fmt: skip
SLASH_COMMENTS = {".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".tf", ".css", ".jsonc"}
MAX_BYTES = 20_000_000
MAX_TERMS = 500
MAX_TERM_LEN = 128
MAX_NODES = 5_000_000  # a YAML or JSON document's nodes, aliases counted once
_NAME = re.compile(r"^[a-z0-9][a-z0-9 ._/:+-]*[a-z0-9]$|^[a-z0-9]$")
_SEP = "-_. "
#: a name is bounded by a non-alphanumeric, or by a seam: lower to upper (zorbixClient), an
#: upper-case run into a capitalised word (HTTPZorbix, ZORBIXClient), or letter to digit
_SEAM = (
    r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])"
)
_LEFT = rf"(?:(?<![A-Za-z0-9])|{_SEAM})"
_RIGHT = rf"(?:(?![A-Za-z0-9])|{_SEAM})"


class LintError(ValueError):
    """A bad vocabulary, allowlist, manifest or baseline (exit 2)."""


def _norm(name: str) -> str:
    return re.sub(r"[\s_]+", "-", name.strip().lower())


_DROP_SEP = str.maketrans("", "", _SEP)
_NOT_ALNUM = re.compile(r"[^0-9a-z]+")


def _key(text: str) -> str:
    """What a match and a name compare by: folded case, separators dropped."""
    return text.casefold().translate(_DROP_SEP)


def _skeleton(text: str) -> str:
    """Only the letters and digits, case-folded: what the prefilter compares, so a name split by
    quotes, a line break and indentation, or any separator still shows."""
    return _NOT_ALNUM.sub("", _visible(text).casefold())


@dataclass(frozen=True)
class Vocabulary:
    by_key: dict[str, str]  # _key(spelling) -> the product the baseline counts under
    pattern: re.Pattern[str] | None
    skeletons: tuple[str, ...]  # a text whose _skeleton() holds none of these holds no name
    own: dict[str, str]  # a provider module's directory (relative) -> its own product

    @property
    def products(self) -> set[str]:
        return set(self.by_key.values())

    def possible(self, text: str) -> bool:
        """False only when no name can be in ``text`` once it is decoded and parsed.  An escape
        can spell a letter the raw text does not show, so text with one is always possible."""
        if _ESCAPE.search(text):
            return True
        sk = _skeleton(text)
        return any(k in sk for k in self.skeletons)

    def count(self, texts: list[str]) -> Counter:
        c: Counter = Counter()
        if self.pattern is None:
            return c
        for m in self.pattern.finditer(_visible("\n".join(texts))):
            c[self.product(m.group(0))] += 1
        return c

    def product(self, matched: str) -> str:
        """The product a match names.  The pattern folds case as ``re`` does, which is not
        always ``str.casefold``; a match that does not key back is matched name by name."""
        found = self.by_key.get(_key(matched))
        if found is not None:
            return found
        for k, prod in self.by_key.items():
            if re.fullmatch(_body(k), matched, re.IGNORECASE):
                return prod
        raise LintError(f"{matched!r} matched but names no product (a lint defect)")


#: letters ``re.IGNORECASE`` folds to an ASCII letter that NFKD does not reach
_FOLD_ASCII = str.maketrans({"\u0131": "i", "\u017f": "s", "\u212a": "K"})


def _visible(text: str) -> str:
    """What a name is matched in: compatibility-decomposed, without combining marks or invisible
    format characters (a zero-width space, a soft hyphen), so a dotted capital I or an accent does
    not hide a name, then recomposed."""
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFKD", text.translate(_FOLD_ASCII))
    return unicodedata.normalize(
        "NFKC",
        "".join(ch for ch in decomposed if unicodedata.category(ch) not in ("Cf", "Mn")),
    )


#: an escape (Python, YAML, JSON, shell) that could spell a letter the raw text does not show,
#: or a line continuation that joins two halves of a name
_ESCAPE = re.compile(r"\\(?:[xuUN0-7]|\r?\n)")


def _body(text: str) -> str:
    parts = [re.escape(p) for p in re.split(rf"[{re.escape(_SEP)}]+", text.lower()) if p]
    return rf"[{re.escape(_SEP)}]?".join(parts)


def _load_yaml(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise LintError(f"{path}: over {MAX_BYTES} bytes")
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_LOADER)
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise LintError(f"{path}: cannot be read ({exc})") from None


_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _spelling(where: str, text: Any) -> str:
    if not isinstance(text, str) or not _NAME.match(_norm(text)) or len(text) > MAX_TERM_LEN:
        raise LintError(
            f"{where}: {text!r} is not a product name (lower-case words, at most {MAX_TERM_LEN} characters)"
        )
    return text


def vocabulary(
    root: Path, overlay: Path | None, roles: Path | None, vocab_doc: Any = None
) -> Vocabulary:
    """The names to match, each mapped to its product, and each provider module's own product."""
    spellings: list[tuple[str, str]] = []  # (product, spelling)
    own: dict[str, str] = {}
    manifests = sorted((root / "examples" / "modules").glob("*/module.yml"))
    manifests += sorted((root / "modules").glob("*/module.yml"))
    if overlay is not None:
        manifests += sorted((overlay / "lab" / "modules").glob("*/module.yml"))
    for mf in manifests:
        doc = _load_yaml(mf)
        if not isinstance(doc, dict) or doc.get("kind") != "provider":
            continue
        prod = doc.get("product")
        if not isinstance(prod, dict) or not isinstance(prod.get("name"), str):
            raise LintError(f"{mf}: a provider needs product.name")
        aliases = prod.get("aliases") or []
        if not isinstance(aliases, list):
            raise LintError(f"{mf}: product.aliases must be a list")
        product = _norm(_spelling(str(mf), prod["name"]))
        for text in [prod["name"], prod.get("display") or "", *aliases]:
            if text:
                spellings.append((product, _spelling(str(mf), text)))
        with contextlib.suppress(ValueError):  # an overlay module: outside the tree being linted
            own[mf.parent.relative_to(root).as_posix()] = product
    if vocab_doc is None:
        if not (root / VOCABULARY).is_file():
            raise LintError(f"{root / VOCABULARY}: missing (is ROOT the repository's top level?)")
        vocab_doc = _load_yaml(root / VOCABULARY)
    for i, p in enumerate(_section(vocab_doc, "products")):
        where = f"{VOCABULARY}: products[{i}]"
        if not isinstance(p, dict):
            raise LintError(f"{where} must be a mapping")
        product = _norm(_spelling(where, p.get("name")))
        if not str(p.get("why", "")).strip():
            raise LintError(f"{where} ({product}) needs a why")
        aliases = p.get("aliases") or []
        if not isinstance(aliases, list):
            raise LintError(f"{where}: aliases must be a list")
        for text in [p["name"], *aliases]:
            spellings.append((product, _spelling(where, text)))
    if roles is not None and roles.is_file():
        try:
            table = json.loads(roles.read_text(encoding="utf-8"))
            for role in (table.get("roles") or {}).values():
                for b in role.get("bindings") or []:
                    mid = b.get("model_id")
                    if isinstance(mid, str) and mid.strip():
                        spellings.append((_norm(mid), _spelling(str(roles), mid)))
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            raise LintError(f"{roles}: cannot be read ({exc})") from None
    by_key: dict[str, str] = {}
    for product, text in spellings:
        k = _key(text)
        if by_key.setdefault(k, product) != product:
            raise LintError(f"{text!r} names both {by_key[k]} and {product}")
    if len(by_key) > MAX_TERMS:
        raise LintError(f"{len(by_key)} names: more than {MAX_TERMS}")
    bodies = sorted({_body(t) for _, t in spellings}, key=lambda b: (-len(b), b))
    alternation = "|".join(bodies)
    pattern = re.compile(rf"{_LEFT}(?i:{alternation}){_RIGHT}") if bodies else None
    skeletons = tuple(sorted({_skeleton(t) for _, t in spellings}))
    return Vocabulary(by_key=by_key, pattern=pattern, skeletons=skeletons, own=own)


def _section(doc: Any, key: str) -> list:
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise LintError(f"{VOCABULARY}: must be a mapping")
    out = doc.get(key) or []
    if not isinstance(out, list):
        raise LintError(f"{VOCABULARY}: {key} must be a list")
    return out


def allowlist(root: Path) -> list[tuple[str, str]]:
    vocab = _load_yaml(root / VOCABULARY) if (root / VOCABULARY).is_file() else {}
    out = []
    for i, e in enumerate(_section(vocab, "allow")):
        if not isinstance(e, dict) or not str(e.get("path", "")).strip():
            raise LintError(f"{VOCABULARY}: allow[{i}] needs a path glob")
        if not str(e.get("reason", "")).strip():
            raise LintError(f"{VOCABULARY}: allow[{i}] ({e['path']}) needs a reason")
        out.append((str(e["path"]), str(e["reason"])))
    return out


def _matches(rel: str, glob: str) -> bool:
    if fnmatch.fnmatchcase(rel, glob):
        return True
    return glob.endswith("/**") and (rel == glob[:-3] or rel.startswith(glob[:-2]))


# ----------------------------------------------------------------------------- text extraction


def _python_texts(text: str) -> list[str]:
    """String and bytes constants as Python reads them (escapes decoded, implicit concatenation
    joined, f-string parts included) and identifiers; comments and docstrings are not read (a
    docstring is skipped as a node, so code on the same line still is)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return text.splitlines()  # unparseable: every line, comments and docstrings too
    docstrings: set[int] = set()
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstrings.add(id(first.value))
        elif isinstance(node, ast.Constant) and id(node) not in docstrings:
            if isinstance(node.value, str):
                out.append(node.value)
            elif isinstance(node.value, bytes):
                out.append(node.value.decode("latin-1"))
    try:
        out += [
            t.string
            for t in tokenize.generate_tokens(io.StringIO(text).readline)
            if t.type == tokenize.NAME
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text.splitlines()
    return out


def _data_texts(doc: Any) -> list[str]:
    """Every key and string value, each shared (aliased) node read once."""
    out: list[str] = []
    seen: set[int] = set()
    stack = [doc]
    nodes = 0
    while stack:
        node = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise LintError(f"more than {MAX_NODES} nodes")
        if isinstance(node, (dict, list, set, frozenset, tuple)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, dict):
            for k, v in node.items():
                stack.append(k)  # a key may be any YAML node, a !!set or a !!binary
                if not (isinstance(v, str) and str(k) in PROSE_KEYS):
                    stack.append(v)
        elif isinstance(node, (list, set, frozenset, tuple)):  # !!set, !!omap, !!pairs
            stack.extend(node)
        elif isinstance(node, str):
            out.append(node)
        elif isinstance(node, bytes):  # !!binary
            out.append(node.decode("latin-1"))
    return out


_BOMS = (
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)
#: suffixes that are never binary: a NUL in one is read through, not a reason to skip the file
TEXT_SUFFIXES = {
    ".py", ".yml", ".yaml", ".json", ".md", ".j2", ".html", ".sql", ".xml", ".js", ".ts", ".css",
    ".go", ".rs", ".tf", ".hcl", ".jsonl", ".csv", ".tmpl",
    *HASH_COMMENTS, *SLASH_COMMENTS,
}  # fmt: skip


def _decode(data: bytes, suffix: str) -> str | None:
    """The text of a file, or None for a binary.  Never a silent skip of text: a BOM names the
    encoding, a NUL at every other byte is UTF-16 without one, UTF-8 is tried, and Latin-1 maps
    every remaining byte to a character."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data[len(bom) :].decode(codec, "replace")
    head = data[:8192]
    if b"\0" in head:
        even, odd = head[::2], head[1:][::2]
        if odd and odd.count(0) > len(odd) * 0.9 and even.count(0) < len(even) * 0.1:
            return data.decode("utf-16-le", "replace")
        if even and even.count(0) > len(even) * 0.9 and odd.count(0) < len(odd) * 0.1:
            return data.decode("utf-16-be", "replace")
        if suffix not in TEXT_SUFFIXES:
            return None  # binary
        data = data.replace(b"\0", b"")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _file_texts(path: Path, rel: str, vocab: Vocabulary | None = None) -> list[str]:
    """The texts to match in a file; with ``vocab``, a file in which no name can match is not
    parsed at all (most of the tree, and the expensive part)."""
    suffix = path.suffix.lower() or path.name.lower()
    with path.open("rb") as fh:
        head = fh.read(8192)
    if _decode(head, suffix) is None:
        return []  # binary, whatever its size
    if path.stat().st_size > MAX_BYTES:
        raise LintError(f"{rel}: over {MAX_BYTES} bytes; allow it with a reason or split it")
    text = _decode(path.read_bytes(), suffix)
    if text is None:
        return []
    if vocab is not None and not vocab.possible(text):
        return []
    if suffix == ".py":
        return _python_texts(text)
    if suffix in (".yml", ".yaml", ".json"):
        try:
            if suffix == ".json":
                return _data_texts(json.loads(text))
            return _data_texts(list(yaml.load_all(text, Loader=_LOADER)))
        except (ValueError, yaml.YAMLError, RecursionError):
            pass  # unparseable: its lines below
    lines = text.splitlines()
    name = path.name.lower()
    hashed = suffix in HASH_COMMENTS or name.startswith(("makefile", "dockerfile", ".env"))
    markers = (("#",) if hashed else ()) + (("//",) if suffix in SLASH_COMMENTS else ())
    if markers:
        lines = [ln for ln in lines if not ln.lstrip().startswith(markers)]
    return lines


def _git(root: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess | None:
    """``git -C ROOT ...``, or None without a git binary."""
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=text, check=False
        )
    except FileNotFoundError:
        return None


def tree_files(root: Path) -> list[str]:
    """The tracked and untracked-but-not-ignored entries under ROOT (relative to it), or every
    file outside a git work tree.  A submodule is listed by its path, for its name."""
    inside = _git(root, "rev-parse", "--is-inside-work-tree")
    if inside is not None and inside.returncode == 0 and inside.stdout.strip() == "true":
        r = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", text=False)
        if r is None or r.returncode:
            raise LintError(f"git ls-files failed in {root}")
        files = {p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p}
        return sorted(f for f in files if os.path.lexists(root / f))
    out = []
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if any(p in SKIP_DIRS for p in rel.split("/")):
            continue
        if path.is_file() or path.is_symlink():
            out.append(rel)
    return sorted(out)


def scan(root: Path, vocab: Vocabulary, allowed: list[str]) -> dict[str, Counter]:
    """``{path: Counter(product -> occurrences)}`` outside the allowed paths; a directory is
    keyed ``dir/`` and counted once for its own name."""
    hits: dict[str, Counter] = {}
    own = sorted(vocab.own.items(), key=lambda kv: -len(kv[0]))

    def count(rel: str, texts: list[str]) -> None:
        c = vocab.count(texts)
        owner = next((p for d, p in own if rel == d + "/" or rel.startswith(d + "/")), None)
        if owner:
            c.pop(owner, None)  # a provider module names its own product, nobody else's
        if c:
            hits.setdefault(rel, Counter()).update(c)

    files = tree_files(root)
    dirs = sorted({"/".join(f.split("/")[:i]) for f in files for i in range(1, f.count("/") + 1)})
    for d in dirs:
        if not any(_matches(d, g) for g in allowed):
            count(d + "/", [d.rsplit("/", 1)[-1]])
    for rel in files:
        if any(_matches(rel, g) for g in allowed):
            continue
        path = root / rel
        count(rel, [path.name])
        if path.is_symlink():
            count(rel, [os.readlink(path)])  # the link's target as written
            target = path.resolve()
            # a link into the tree is read as what it points at, under the link's own path, so a
            # core path linked to an allowed file is still linted where it is used
            if target.is_file() and target.is_relative_to(root):
                count(rel, _file_texts(target, rel, vocab))
        elif path.is_file():
            count(rel, _file_texts(path, rel, vocab))
    return dict(sorted(hits.items()))


# ----------------------------------------------------------------------------- the baseline


def parse_baseline(text: str, where: str) -> dict[str, dict[str, int]]:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise LintError(f"{where}: cannot be read ({exc})") from None
    counts = doc.get("counts") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(counts, dict):
        raise LintError(f"{where}: needs version 1 and counts {{path: {{product: n}}}}")
    for p, c in counts.items():
        if not isinstance(c, dict) or not all(type(n) is int and n > 0 for n in c.values()):
            raise LintError(f"{where}: counts[{p!r}] must map product -> a positive count")
    return counts


def load_baseline(path: Path) -> dict[str, dict[str, int]]:
    if not path.is_file():
        return {}
    try:
        return parse_baseline(path.read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise LintError(f"{path}: cannot be read ({exc})") from None


def totals(counts: dict[str, dict[str, int]] | dict[str, Counter]) -> Counter:
    t: Counter = Counter()
    for c in counts.values():
        t.update(c)
    return t


def compare(
    hits: dict[str, Counter], base: dict[str, dict[str, int]]
) -> tuple[list[str], list[str]]:
    """(new: names beyond the baseline, stale: baseline entries above what is there)."""
    new, stale = [], []
    for rel, c in hits.items():
        for product, n in sorted(c.items()):
            allowed = base.get(rel, {}).get(product, 0)
            if n > allowed:
                new.append(
                    f"{rel}: {product} x{n} (baseline {allowed}): name the slot, not the product"
                )
    for rel, c in sorted(base.items()):
        for product, n in sorted(c.items()):
            have = hits.get(rel, Counter()).get(product, 0)
            if have < n:
                stale.append(
                    f"{rel}: {product} baseline {n}, now {have}: run --update (the baseline only shrinks)"
                )
    return new, stale


def grown(now: dict[str, Any], then: dict[str, Any]) -> list[str]:
    """Products whose total is above ``then``'s (a product ``then`` lacks counts from zero)."""
    t_now, t_then = totals(now), totals(then)
    return [
        f"{p}: {t_now[p]} in total, {t_then.get(p, 0)} before"
        for p in sorted(t_now)
        if t_now[p] > t_then.get(p, 0)
    ]


def _prefix(root: Path) -> str:
    r = _git(root, "rev-parse", "--show-prefix")
    return r.stdout.strip() if r is not None and r.returncode == 0 else ""


def vocabulary_at(root: Path, rev: str) -> Vocabulary:
    """The vocabulary as it was at ``rev``: the same files, read from git."""
    pre = _prefix(root)
    wanted = ["examples/modules", "modules", VOCABULARY, ROLES]
    r = _git(root, "ls-tree", "-r", "--name-only", rev, "--", *(pre + w for w in wanted))
    if r is None or r.returncode:
        raise LintError(f"--base {rev}: cannot list its tree")
    with tempfile.TemporaryDirectory(prefix="product-names-base.") as tmp:
        base = Path(tmp)
        for full in r.stdout.splitlines():
            rel = full[len(pre) :]
            if not (
                rel in (VOCABULARY, ROLES) or fnmatch.fnmatchcase(rel, "*modules/*/module.yml")
            ):
                continue
            blob = _git(root, "show", f"{rev}:{full}", text=False)
            if blob is None or blob.returncode:
                raise LintError(f"--base {rev}: cannot read {rel}")
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_bytes(blob.stdout)
        if not (base / VOCABULARY).is_file():
            return Vocabulary(by_key={}, pattern=None, skeletons=(), own={})
        return vocabulary(base, None, base / ROLES)


def renames(root: Path, rev: str) -> dict[str, str]:
    """``{new path: old path}`` for the files git sees as renamed or copied since ``rev``."""
    pre = _prefix(root)
    r = _git(root, "diff", "-M", "-C", "--name-status", "-z", rev, "--", ".")
    if r is None or r.returncode:
        raise LintError(f"--base {rev}: git diff failed")
    parts = r.stdout.split("\0")
    out: dict[str, str] = {}
    i = 0
    while i < len(parts) - 1:
        status = parts[i]
        if status[:1] in ("R", "C"):
            old, new = parts[i + 1], parts[i + 2]
            out[new[len(pre) :]] = old[len(pre) :]
            i += 3
        else:
            i += 2
    return out


def retired(root: Path) -> dict[str, str]:
    """``tools/product_names.yml`` ``retired:``: names deliberately no longer linted, with why."""
    out = {}
    for i, e in enumerate(_section(_load_yaml(root / VOCABULARY), "retired")):
        if not isinstance(e, dict) or not isinstance(e.get("name"), str):
            raise LintError(f"{VOCABULARY}: retired[{i}] needs a name")
        if not str(e.get("reason", "")).strip():
            raise LintError(f"{VOCABULARY}: retired[{i}] ({e['name']}) needs a reason")
        out[_key(e["name"])] = str(e["reason"])
    return out


def against_base(
    root: Path, rev: str, base: dict[str, dict[str, int]], vocab: Vocabulary
) -> list[str]:
    """The committed baseline and vocabulary against those at ``rev``: no path's count above
    its count there (a renamed or copied file keeps its old path's counts), and no name linted
    there that is not linted now, unless ``retired:`` says why."""
    r = _git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    if r is None or r.returncode:
        raise LintError(f"--base {rev}: not a commit here")
    problems = []
    old = _git(root, "show", f"{rev}:{_prefix(root)}{BASELINE}")
    if old is not None and old.returncode == 0:
        then = parse_baseline(old.stdout, f"{BASELINE}@{rev[:12]}")
        moved = renames(root, rev)
        for rel, c in sorted(base.items()):
            source = then.get(rel) or then.get(moved.get(rel, ""), {})
            for product, n in sorted(c.items()):
                if n > source.get(product, 0):
                    problems.append(
                        f"{BASELINE}: {rel}: {product} {n}, {source.get(product, 0)} at "
                        f"{rev[:12]}: the baseline never grows (name the slot, move the code into "
                        "its provider module, or allow the path with a reason)"
                    )
    gone = set(vocabulary_at(root, rev).by_key) - set(vocab.by_key) - set(retired(root))
    problems += [
        f"{VOCABULARY}: {k!r} was linted at {rev[:12]} and is no longer: a name leaves the "
        "vocabulary only through retired: (with a reason) or by moving to its provider's "
        "product block"
        for k in sorted(gone)
    ]
    return problems


def write_baseline(path: Path, counts: dict[str, Any]) -> None:
    """Atomically, and never through a symbolic link."""
    if path.is_symlink():
        raise LintError(f"{path}: a symbolic link; refusing to write through it")
    doc = {"version": 1, "counts": {r: dict(sorted(c.items())) for r, c in sorted(counts.items())}}
    atomic_write_text(path, json.dumps(doc, indent=1, sort_keys=True) + "\n", mode=0o644)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # a path that is not UTF-8 prints, never crashes
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="backslashreplace")
    try:
        return _main(argv)
    except LintError as exc:
        print(f"product_name_lint: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # an internal failure: "could not measure", never a pass or a fail
        print(f"product_name_lint: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 100


def _main(argv: list[str] | None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--overlay", type=Path, help="a private overlay checkout (its lab/modules/)")
    ap.add_argument("--roles", type=Path, help=f"the model role table (default ROOT/{ROLES})")
    ap.add_argument("--baseline", type=Path, help=f"default ROOT/{BASELINE}")
    ap.add_argument("--json", action="store_true")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--update",
        action="store_true",
        help="rewrite the baseline to what is there; refused when any product's total would rise",
    )
    mode.add_argument(
        "--init", action="store_true", help="write the baseline from scratch (first adoption only)"
    )
    base = ap.add_mutually_exclusive_group()
    base.add_argument("--base", help="a commit whose baseline and vocabulary may not be exceeded")
    base.add_argument(
        "--ci-base",
        action="store_true",
        help="pick --base like tools/schema_check.py --ci-base (GITHUB_EVENT_NAME, HNX_PR_BASE, HNX_PUSH_BEFORE)",
    )
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    baseline = args.baseline or root / BASELINE
    vocab = vocabulary(root, args.overlay, args.roles or root / ROLES)
    globs = [*ALWAYS_ALLOWED, *(g for g, _ in allowlist(root))]
    hits = scan(root, vocab, globs)
    if args.init:
        if baseline.exists() or baseline.is_symlink():
            raise LintError(f"{baseline} exists; --init is for the first adoption")
        write_baseline(baseline, hits)
        print(f"product_name_lint: wrote {baseline} ({len(hits)} path(s))")
        return 0
    base_counts = load_baseline(baseline)
    if args.update:
        rises = grown(hits, base_counts)
        if rises:
            print("\n".join(rises), file=sys.stderr)
            print(
                "product_name_lint: refusing to update: a product's total would rise",
                file=sys.stderr,
            )
            return 1
        before = sum(totals(base_counts).values())
        write_baseline(baseline, hits)
        after = sum(totals(hits).values())
        print(f"product_name_lint: baseline updated ({before} -> {after} occurrence(s))")
        return 0
    rev = args.base
    if rev is not None and not rev.strip():
        raise LintError("--base needs a commit (an empty value would skip the check)")
    if args.ci_base:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from schema_check import ci_base

        try:
            rev, why = ci_base(
                root,
                os.environ.get("GITHUB_EVENT_NAME", ""),
                os.environ.get("HNX_PR_BASE", ""),
                os.environ.get("HNX_PUSH_BEFORE", ""),
            )
        except ValueError as exc:
            raise LintError(str(exc)) from None
        print(f"product_name_lint: base {rev or '-'} ({why})")
    new, stale = compare(hits, base_counts)
    grew = against_base(root, rev, base_counts, vocab) if rev else []
    if args.json:
        print(
            json.dumps(
                {"new": new, "stale": stale, "grown": grew, "names": len(vocab.by_key)}, indent=2
            )
        )
    else:
        for line in new + stale + grew:
            print(line)
        total = sum(totals(hits).values())
        print(
            f"product_name_lint: {len(new)} new, {len(stale)} stale, {len(grew)} grown; "
            f"{len(vocab.by_key)} name(s), {total} baselined occurrence(s) in {len(hits)} path(s)"
        )
    return 1 if new or stale or grew else 0


if __name__ == "__main__":
    sys.exit(main())
