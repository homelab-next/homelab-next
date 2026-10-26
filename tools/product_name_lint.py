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
  (``git ls-files``; a directory walk outside a git checkout): Python string and bytes constants
  and identifiers (comments and docstrings are skipped); every key and string value of YAML and
  JSON, except the string value of a prose key (``description``, ``title``, ``$comment``,
  ``summary``, ``reason``, ``why``, ``purpose``, ``help``); the lines of every other text file
  (any suffix, extensionless included), without the comment lines of formats known to use ``#``
  or ``//``; and every file and directory name.  A binary file (a NUL byte) is skipped; a text file
  over 20 MB is an error, never a silent skip.

**Matching** is case-insensitive after NFKC normalisation with invisible format characters removed,
with ``-``, ``_``, ``.`` and a space alike between the parts of a name (or none: ``uptimekuma``),
and bounded: no letter or digit on either side, except at a camel-case or letter/digit seam
(``OpenbaoClient``, ``getOpenbao``, ``openbao2`` count; ``notopenbao`` and ``OPENBAOADDR`` do not).
It catches the ordinary spellings, not deliberate obfuscation (``"open" + "bao"``, an encoded
string); that is review's job, which is why this file, the vocabulary and the baseline are owned.

**The baseline** (``tools/product_names.baseline.json``) holds the counts per path and product:
a count above it, or a path or product not in it, fails; so does an entry above what is there.
``--update`` rewrites it to what is there, refused when any product's total would rise (so a moved
file keeps its debt, and debt never grows).  ``--base REV`` / ``--ci-base`` (CI) also compare the
committed baseline with the one at the base commit: no product's total may rise and no product the
base's vocabulary listed may leave it, so neither can be done by hand-editing either file.

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
import tokenize
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homelabnext.state.store import atomic_write_text  # noqa: E402

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
MAX_TERMS = 2_000
MAX_TERM_LEN = 128
MAX_NODES = 5_000_000  # a YAML or JSON document's nodes, aliases counted once
_NAME = re.compile(r"^[a-z0-9][a-z0-9 ._/:+-]*[a-z0-9]$|^[a-z0-9]$")
_SEP = "-_. "
_LEFT = r"(?:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z]))"
_RIGHT = r"(?:(?![A-Za-z0-9])|(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z]))"


class LintError(ValueError):
    """A bad vocabulary, allowlist, manifest or baseline (exit 2)."""


def _norm(name: str) -> str:
    return re.sub(r"[\s_]+", "-", name.strip().lower())


_DROP_SEP = str.maketrans("", "", _SEP)


def _key(text: str) -> str:
    """What a match and a name compare by: lower case, separators dropped."""
    return text.lower().translate(_DROP_SEP)


@dataclass(frozen=True)
class Vocabulary:
    by_key: dict[str, str]  # _key(spelling) -> the product the baseline counts under
    pattern: re.Pattern[str] | None
    keys: tuple[str, ...]  # a text whose _key() holds none of these cannot hold a name
    own: dict[str, str]  # a provider module's directory (relative) -> its own product

    @property
    def products(self) -> set[str]:
        return set(self.by_key.values())

    def possible(self, text: str) -> bool:
        keyed = _key(_visible(text))
        return any(k in keyed for k in self.keys)

    def count(self, texts: list[str]) -> Counter:
        c: Counter = Counter()
        if self.pattern is None:
            return c
        for m in self.pattern.finditer(_visible("\n".join(texts))):
            c[self.by_key[_key(m.group(0))]] += 1
        return c


def _visible(text: str) -> str:
    """NFKC, without invisible format characters (a zero-width space, a soft hyphen)."""
    if text.isascii():
        return text
    return "".join(
        ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf"
    )


#: a Python escape that could spell a letter the raw text does not show
_PY_ESCAPE = re.compile(r"\\(?:x|u|U|N\{|[0-7])")


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
        vocab_doc = _load_yaml(root / VOCABULARY) if (root / VOCABULARY).is_file() else {}
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
    return Vocabulary(by_key=by_key, pattern=pattern, keys=tuple(sorted(by_key)), own=own)


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


def _docstrings(body: list[ast.stmt], out: set[tuple[int, int]]) -> None:
    """The start of every docstring, through statement lists only (no expression walk)."""
    for node in body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            _docstring(node.body, out)
        for field in ("body", "orelse", "finalbody"):
            sub = getattr(node, field, None)
            if isinstance(sub, list):
                _docstrings(sub, out)
        for clause in [*getattr(node, "handlers", []), *getattr(node, "cases", [])]:
            _docstrings(clause.body, out)


def _docstring(body: list[ast.stmt], out: set[tuple[int, int]]) -> None:
    first = body[0] if body else None
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        out.add((first.value.lineno, first.value.col_offset))


def _python_texts(text: str) -> list[str]:
    """String and bytes literals (escapes decoded) and identifiers; comments and docstrings are
    not read (a docstring is skipped by its exact position, so code beside it still is)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return text.splitlines()  # unparseable: every line, comments and docstrings too
    docstrings: set[tuple[int, int]] = set()
    _docstring(tree.body, docstrings)
    _docstrings(tree.body, docstrings)
    out: list[str] = []
    in_doc = False
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING:
                # an implicitly concatenated docstring is several tokens: skip to the statement's end
                in_doc = in_doc or tok.start in docstrings
                if in_doc:
                    continue
                try:
                    value = ast.literal_eval(tok.string)
                except (ValueError, SyntaxError, MemoryError, RecursionError):
                    value = tok.string  # an f-string (before 3.12): as written
                out.append(value.decode("latin-1") if isinstance(value, bytes) else str(value))
            elif tok.type not in (tokenize.NL, tokenize.COMMENT):
                in_doc = False
                if tok.type == tokenize.NAME or tok.type == getattr(tokenize, "FSTRING_MIDDLE", -1):
                    out.append(tok.string)
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
        if isinstance(node, (dict, list)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, dict):
            for k, v in node.items():
                out.append(str(k))
                if not (isinstance(v, str) and str(k) in PROSE_KEYS):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            out.append(node)
    return out


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")  # never a silent skip: every byte maps to a character


def _file_texts(path: Path, rel: str, vocab: Vocabulary | None = None) -> list[str]:
    """The texts to match in a file; with ``vocab``, a file in which no name can match is not
    parsed at all (most of the tree, and the expensive part)."""
    if path.stat().st_size > MAX_BYTES:
        raise LintError(f"{rel}: over {MAX_BYTES} bytes; allow it with a reason or split it")
    data = path.read_bytes()
    if b"\0" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return []  # binary
    text = _decode(data)
    suffix = path.suffix.lower() or path.name.lower()
    if (
        vocab is not None
        and not vocab.possible(text)
        and not (suffix == ".py" and _PY_ESCAPE.search(text))
    ):
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


def tree_files(root: Path) -> list[str]:
    """The tracked and untracked-but-not-ignored files (relative), or every file outside git."""
    r = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=False,
    )
    inside = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if r.returncode == 0 and inside.returncode == 0 and Path(inside.stdout.strip()) == root:
        files = {p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p}
        return sorted(f for f in files if (root / f).is_file() or (root / f).is_symlink())
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
            count(rel, [os.readlink(path)])  # the link's target, never its content
        else:
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


def against_base(
    root: Path, rev: str, base: dict[str, dict[str, int]], vocab: Vocabulary
) -> list[str]:
    """The committed baseline and vocabulary against those at ``rev``."""

    def show(path: str) -> str | None:
        r = subprocess.run(
            ["git", "-C", str(root), "show", f"{rev}:{path}"], capture_output=True, text=True
        )
        return r.stdout if r.returncode == 0 else None

    if subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
        capture_output=True,
    ).returncode:
        raise LintError(f"--base {rev}: not a commit here")
    problems = []
    old = show(BASELINE)
    if old is not None:
        problems += [
            f"{BASELINE}: {g} at {rev[:12]}: the baseline only shrinks (move the code, or allow "
            "the path with a reason)"
            for g in grown(base, parse_baseline(old, f"{BASELINE}@{rev[:12]}"))
        ]
    old_vocab = show(VOCABULARY)
    if old_vocab is not None:
        try:
            doc = yaml.load(old_vocab, Loader=_LOADER)
        except yaml.YAMLError as exc:
            raise LintError(f"{VOCABULARY}@{rev[:12]}: cannot be read ({exc})") from None
        for p in _section(doc, "products"):
            name = _norm(str(p.get("name", ""))) if isinstance(p, dict) else ""
            if name and name not in vocab.products:
                problems.append(
                    f"{VOCABULARY}: {name} was linted at {rev[:12]} and is no longer: a product "
                    "leaves products: only for its provider module's product block"
                )
    return problems


def write_baseline(path: Path, counts: dict[str, Any]) -> None:
    """Atomically, and never through a symbolic link."""
    if path.is_symlink():
        raise LintError(f"{path}: a symbolic link; refusing to write through it")
    doc = {"version": 1, "counts": {r: dict(sorted(c.items())) for r, c in sorted(counts.items())}}
    atomic_write_text(path, json.dumps(doc, indent=1, sort_keys=True) + "\n", mode=0o644)


def main(argv: list[str] | None = None) -> int:
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
