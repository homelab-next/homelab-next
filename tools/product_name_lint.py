#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: product-name-lint
#   kind: check
#   purpose: Fail when a product name appears in the core outside a provider module, beyond the shrinking baseline.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:gates]
#   invariant: [X-11]
#   inputs: the tree; tools/product_names.yml; tools/product_names.baseline.json; the role table
#   outputs: one line per violation; --shrink rewrites the baseline downward
#   exit:
#     "0": clean
#     "1": violations (a new name, or a baseline entry above what is there)
#     "2": usage error or a bad vocabulary, allowlist or baseline
"""The product-name lint (ADR-0027 rule 1; docs/modules.md, "The product-name lint").

A product's name may appear only in its provider module, in site configuration and in prose:
the core and the feature and core modules name slots, never products, so a swap never needs a
code change.  The lint reads:

* **the vocabulary**: every provider manifest's ``product.name``, ``product.display``
  (lower-cased, spaces as ``-``) and ``product.aliases`` (``examples/modules/*/module.yml``, the
  public ``modules/*/module.yml``, and ``--overlay DIR/lab/modules/*/module.yml``); the products
  without a provider module yet (``tools/product_names.yml`` ``products:``); and the model
  identifiers of the role table (``bindings[].model_id``, ``--roles``).  Environment names are
  covered by the same match (``NORTHWIND_OBJECTS_ENDPOINT`` names ``northwind-objects``);
* **where a name is allowed**: inside a provider module's directory, in site configuration
  (``examples/modules/sites/``, ``examples/private-overlay/``, an overlay's ``lab/``), in Markdown
  prose (ADRs and the changelog included), and under the reviewed path globs of
  ``tools/product_names.yml`` ``allow:`` (each with a reason);
* **what is linted** everywhere else: Python string literals and identifiers (``tokenize``:
  comments and docstrings are skipped), every key and string value of YAML and JSON (so a schema's
  ``enum``, ``default`` and ``const`` and a CLI's choices are covered; comments are not values),
  the non-comment lines of other text files, and every file and directory name.

**Matching** is case-insensitive and bounded (no letter or digit on either side), with ``-``,
``_`` and a space alike.  **The baseline** (``tools/product_names.baseline.json``) holds today's
counts per path and product: a count above it, or a path or product not in it, fails; so does a
baseline entry above what is there, because the baseline only shrinks (``--shrink`` rewrites it
downward and refuses while anything is new).

Usage:
  python tools/product_name_lint.py [ROOT] [--overlay DIR] [--roles FILE] [--json] [--shrink]
Exit: 0 clean, 1 violations, 2 usage or a bad input file.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import fnmatch
import io
import json
import re
import sys
import tokenize
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

VOCABULARY = "tools/product_names.yml"
BASELINE = "tools/product_names.baseline.json"
ROLES = "examples/model_roles.json"
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "build",
    "dist",
    ".egg-info",
}
#: paths where a product name belongs: site configuration and prose
ALWAYS_ALLOWED = (
    "examples/modules/sites/**",
    "examples/private-overlay/**",
    "lab/**",
    "*.md",
    "**/*.md",
    VOCABULARY,
    BASELINE,
    ROLES,  # the role table is where model ids belong
)
TEXT_SUFFIXES = {
    ".sh",
    ".j2",
    ".cfg",
    ".toml",
    ".ini",
    ".conf",
    ".service",
    ".timer",
    ".tf",
    ".go",
    ".txt",
}
MAX_BYTES = 2_000_000
_NAME = re.compile(r"^[a-z0-9][a-z0-9 ._-]*[a-z0-9]$|^[a-z0-9]$")


class LintError(ValueError):
    """A bad vocabulary, allowlist or baseline (exit 2)."""


@dataclass(frozen=True)
class Term:
    product: str  # the canonical name the baseline counts under
    pattern: re.Pattern[str]


def _norm(name: str) -> str:
    return re.sub(r"[\s_]+", "-", name.strip().lower())


def _term(product: str, text: str) -> Term:
    parts = [re.escape(p) for p in re.split(r"[-_ ]+", _norm(text)) if p]
    if not parts:
        raise LintError(f"{product}: an empty name")
    body = r"[-_ ]?".join(parts) if len(parts) == 1 else r"[-_ ]".join(parts)
    return Term(product, re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE))


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LintError(f"{path}: cannot be read ({exc})") from None


def vocabulary(
    root: Path, overlay: Path | None, roles: Path | None
) -> tuple[list[Term], list[str]]:
    """The terms to match and the provider module directories (relative) where they are allowed."""
    terms: list[Term] = []
    provider_dirs: list[str] = []
    manifests = sorted((root / "examples" / "modules").glob("*/module.yml"))
    manifests += sorted((root / "modules").glob("*/module.yml"))
    if overlay is not None:
        manifests += sorted((overlay / "lab" / "modules").glob("*/module.yml"))
    for mf in manifests:
        doc = _load_yaml(mf)
        if not isinstance(doc, dict) or doc.get("kind") != "provider":
            continue
        prod = doc.get("product") or {}
        name = prod.get("name")
        if not isinstance(name, str):
            raise LintError(f"{mf}: a provider without product.name")
        product = _norm(name)
        for text in [name, prod.get("display") or "", *(prod.get("aliases") or [])]:
            if text:
                terms.append(_term(product, str(text)))
        with contextlib.suppress(ValueError):  # an overlay module: outside the tree being linted
            provider_dirs.append(mf.parent.relative_to(root).as_posix())
    vocab = _load_yaml(root / VOCABULARY) if (root / VOCABULARY).is_file() else {}
    for i, p in enumerate((vocab or {}).get("products") or []):
        if (
            not isinstance(p, dict)
            or not isinstance(p.get("name"), str)
            or not _NAME.match(_norm(p["name"]))
        ):
            raise LintError(f"{VOCABULARY}: products[{i}] needs a lower-case name")
        if not str(p.get("why", "")).strip():
            raise LintError(f"{VOCABULARY}: products[{i}] ({p['name']}) needs a why")
        product = _norm(p["name"])
        for text in [p["name"], *(p.get("aliases") or [])]:
            terms.append(_term(product, str(text)))
    if roles is not None and roles.is_file():
        try:
            table = json.loads(roles.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LintError(f"{roles}: cannot be read ({exc})") from None
        for role in (table.get("roles") or {}).values():
            for b in role.get("bindings") or []:
                mid = b.get("model_id")
                if isinstance(mid, str) and mid.strip():
                    terms.append(_term(_norm(mid), mid))
    unique: dict[tuple[str, str], Term] = {}
    for t in terms:  # a name and its display name often normalise to one term: count it once
        unique.setdefault((t.product, t.pattern.pattern), t)
    return list(unique.values()), provider_dirs


def allowlist(root: Path) -> list[tuple[str, str]]:
    vocab = _load_yaml(root / VOCABULARY) if (root / VOCABULARY).is_file() else {}
    out = []
    for i, e in enumerate((vocab or {}).get("allow") or []):
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


def _allowed(rel: str, globs: list[str]) -> bool:
    return any(_matches(rel, g) for g in globs)


# ----------------------------------------------------------------------------- text extraction


def _python_texts(text: str) -> list[str]:
    """String literals and identifiers, without comments and docstrings."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    doc_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            first = body[0] if body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                doc_lines.update(range(body[0].lineno, (body[0].end_lineno or body[0].lineno) + 1))
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING and tok.start[0] in doc_lines:
                continue
            if tok.type in (tokenize.STRING, tokenize.NAME) or tok.type == getattr(
                tokenize, "FSTRING_MIDDLE", -1
            ):
                out.append(tok.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    return out


def _data_texts(doc: Any) -> list[str]:
    out: list[str] = []
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                out.append(str(k))
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            out.append(node)
    return out


def _file_texts(path: Path) -> list[str]:
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    suffix = path.suffix.lower()
    if suffix == ".py":
        return _python_texts(text)
    if suffix in (".yml", ".yaml"):
        try:
            return _data_texts(list(yaml.safe_load_all(text)))
        except yaml.YAMLError:
            pass
    elif suffix == ".json":
        try:
            return _data_texts(json.loads(text))
        except ValueError:
            pass
    elif suffix not in TEXT_SUFFIXES and suffix not in (".yml", ".yaml", ".json"):
        return []
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith(("#", "//"))]


def scan(root: Path, terms: list[Term], allowed: list[str]) -> dict[str, Counter]:
    """``{path: Counter(product -> occurrences)}`` outside the allowed paths."""
    hits: dict[str, Counter] = {}

    def count(rel: str, texts: list[str]) -> None:
        c: Counter = Counter()
        for t in texts:
            for term in terms:
                n = len(term.pattern.findall(t))
                if n:
                    c[term.product] += n
        if c:
            hits.setdefault(rel, Counter()).update(c)

    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        parts = rel.split("/")
        if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts):
            continue
        if _allowed(rel, allowed) or path.is_symlink():
            continue
        count(rel + ("/" if path.is_dir() else ""), [path.name])  # the name itself
        if path.is_file():
            count(rel, _file_texts(path))
    return dict(sorted(hits.items()))


# ----------------------------------------------------------------------------- the baseline


def load_baseline(path: Path) -> dict[str, dict[str, int]]:
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LintError(f"{path}: cannot be read ({exc})") from None
    counts = doc.get("counts") if isinstance(doc, dict) else None
    if doc.get("version") != 1 or not isinstance(counts, dict):
        raise LintError(f"{path}: needs version 1 and counts {{path: {{product: n}}}}")
    for p, c in counts.items():
        if not isinstance(c, dict) or not all(isinstance(n, int) and n > 0 for n in c.values()):
            raise LintError(f"{path}: counts[{p!r}] must map product -> a positive count")
    return counts


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
                    f"{rel}: {product} baseline {n}, now {have}: run --shrink (the baseline only shrinks)"
                )
    return new, stale


def shrunk(hits: dict[str, Counter], base: dict[str, dict[str, int]]) -> dict[str, Any]:
    counts: dict[str, dict[str, int]] = {}
    for rel, c in sorted(base.items()):
        for product, n in sorted(c.items()):
            keep = min(n, hits.get(rel, Counter()).get(product, 0))
            if keep:
                counts.setdefault(rel, {})[product] = keep
    return {"version": 1, "counts": counts}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--overlay", type=Path, help="a private overlay checkout (its lab/modules/)")
    ap.add_argument("--roles", type=Path, help=f"the model role table (default ROOT/{ROLES})")
    ap.add_argument("--baseline", type=Path, help=f"default ROOT/{BASELINE}")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--shrink", action="store_true", help="lower the baseline to what is there")
    ap.add_argument(
        "--init", action="store_true", help="write the baseline from scratch (first adoption only)"
    )
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    baseline = args.baseline or root / BASELINE
    try:
        terms, provider_dirs = vocabulary(root, args.overlay, args.roles or root / ROLES)
        globs = [
            *ALWAYS_ALLOWED,
            *(d + "/**" for d in provider_dirs),
            *(g for g, _ in allowlist(root)),
        ]
        hits = scan(root, terms, globs)
        if args.init:
            if baseline.exists():
                print(
                    f"product_name_lint: {baseline} exists; --init is for the first adoption",
                    file=sys.stderr,
                )
                return 2
            doc = {"version": 1, "counts": {r: dict(sorted(c.items())) for r, c in hits.items()}}
            baseline.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            print(f"product_name_lint: wrote {baseline} ({len(hits)} path(s))")
            return 0
        base = load_baseline(baseline)
    except LintError as exc:
        print(f"product_name_lint: {exc}", file=sys.stderr)
        return 2
    new, stale = compare(hits, base)
    if args.shrink:
        if new:
            print("\n".join(new), file=sys.stderr)
            print("product_name_lint: refusing to shrink while names are new", file=sys.stderr)
            return 1
        baseline.write_text(
            json.dumps(shrunk(hits, base), indent=1, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"product_name_lint: baseline shrunk ({len(stale)} entry(ies) lowered)")
        return 0
    if args.json:
        print(json.dumps({"new": new, "stale": stale, "terms": len(terms)}, indent=2))
    else:
        for line in new + stale:
            print(line)
        total = sum(sum(c.values()) for c in hits.values())
        print(
            f"product_name_lint: {len(new)} new, {len(stale)} stale; {len(terms)} term(s), "
            f"{total} baselined occurrence(s) in {len(hits)} path(s)"
        )
    return 1 if new or stale else 0


if __name__ == "__main__":
    sys.exit(main())
