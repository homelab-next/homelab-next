#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: dup-check
#   kind: check
#   purpose: Fail when copy-pasted Python appears that the committed duplication baseline does not hold; the baseline only shrinks.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:dup-baseline, make:dup-check]
#   invariant: [M-03]
#   inputs: the tracked Python files and tools/dup_check.baseline.json
#   outputs: one line per new clone (both copies) or stale baseline entry; the rewritten baseline with --update-baseline
#   exit:
#     "0": no clone beyond the baseline and no stale entry
#     "1": a new or grown clone, or a stale baseline entry
#     "2": usage error, a bad baseline, or an update that would raise the total
"""Gate: duplicated code is a ratchet, never a growth.

Tokenises every tracked Python file (``git ls-files``, the stdlib ``tokenize`` module), finds token
windows that occur more than once, merges overlapping windows into clone pairs and reports the
``file:line`` range of both copies. A clone counts when it is at least ``--min-tokens`` tokens and
``--min-lines`` lines long in both copies.

Modes (``--mode``):
  exact       tokens compared as written. The default: on this tree every clone it finds is a
              real copy (a helper, a lifecycle block, a lint's file walk), and an interface
              signature implemented by several adapters is the only repetition it shares with
              ordinary code.
  normalised  identifiers become ``$id``, strings ``$str``, numbers ``$num``; keywords, operators
              and the indentation structure stay, so a copy whose names were changed is still the
              same code. An audit mode, not the gate: it also matches boilerplate that is only
              alike in shape (dataclass field lists, exception classes, literal tables), about
              four times as much as exact mode on this tree.

Always ignored: comments, blank lines, the encoding marker, docstrings, and module-level
``import`` / ``from ... import`` statements (an import block is boilerplate in either mode).

Scope (decided, not inherited): tracked ``*.py`` minus test code (``tests/`` anywhere,
``test_*.py``, ``conftest.py``: fixtures and parametrised cases repeat on purpose and a shared
test helper is not where drift hurts), ``schemas/_frozen/`` (frozen copies by design) and files
whose first lines say ``@generated`` or ``DO NOT EDIT`` (regenerated, never hand-edited). Shell
scripts are out of scope: the tree has a handful and none of them is copy-pasted.

The baseline (``tools/dup_check.baseline.json``) holds today's clones keyed by a hash of the
clone's normalised tokens, never by line numbers, so moving code or editing elsewhere does not
churn it. Each entry also carries winnowed fingerprints of its tokens: a clone that shrank
(one copy was edited, so less of it is duplicated) is still covered by its entry, a clone that
grew or a third copy is not. ``check`` fails on a clone the baseline does not cover and on a
baseline entry that matches nothing (the clone was removed: run ``--update-baseline`` so the file
shrinks). ``--update-baseline`` rewrites the file and refuses to raise the duplicated-line total
unless ``--allow-increase REASON`` is given; the reason is kept in the file.

Split with M-03 (the ``shared_helpers_lint`` tool): M-03 is semantic. It flags a notify, state or
lake helper written outside its shared library whether or not it was copied, and its allowlist
says why an exception may stand. This gate is textual: it flags copy-paste anywhere, whatever it
does. A copied seam helper trips both, and the M-03 fix (call the library) removes both
findings; nothing here is excused by the M-03 allowlist, and M-03 does not read this baseline.

Usage: python tools/dup_check.py [ROOT] [--baseline FILE] [--update-baseline [--allow-increase R]]
       [--mode exact|normalised] [--min-tokens N] [--min-lines N] [--list] [--json]
Exit: 0 clean, 1 new/grown clone or stale entry, 2 usage, bad baseline or a refused increase.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import keyword
import subprocess
import sys
import token as tk
import tokenize
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BASELINE = "tools/dup_check.baseline.json"
DEFAULTS = {"mode": "exact", "min_tokens": 50, "min_lines": 5}
SCHEMA = 1
SKIP_TYPES = {tk.COMMENT, tk.NL, tk.ENCODING, tk.ENDMARKER}
FSTRING_PARTS = {getattr(tk, n) for n in ("FSTRING_START", "FSTRING_MIDDLE") if hasattr(tk, n)}
STRUCTURE = {";", "{", "}"}  # NEWLINE, INDENT, DEDENT
GENERATED_MARKS = ("@generated", "DO NOT EDIT")


@dataclass
class Source:
    path: str
    norm: list[str]  # the comparable token texts
    lines: list[int]  # the source line of each token
    nlines: int


@dataclass
class Clone:
    a: tuple[str, int, int]  # (path, first line, last line)
    b: tuple[str, int, int]
    tokens: list[str] = field(repr=False)
    key: str = ""
    fps: frozenset = frozenset()

    @property
    def size(self) -> int:
        return len(self.tokens)

    def where(self) -> str:
        return " <-> ".join(f"{p}:{s}-{e}" for p, s, e in (self.a, self.b))


# ---------------------------------------------------------------- scope and tokenising


def in_scope(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if not name.endswith(".py") or "tests" in parts[:-1]:
        return False
    if rel.startswith("schemas/_frozen/"):
        return False
    return not (name.startswith("test_") or name == "conftest.py")


def tracked_python(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--", "*.py"],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            f"dup_check: {root} is not a git checkout ({exc.__class__.__name__})"
        ) from None
    rels = [r for r in out.decode().split("\0") if r]
    return sorted(r for r in rels if in_scope(r) and (root / r).is_file())


def tokens_of(text: str, mode: str) -> tuple[list[str], list[int]]:
    """The comparable tokens of ``text`` and their lines (raises on untokenisable source)."""
    norm: list[str] = []
    lines: list[int] = []
    line_start = True  # at the start of a logical line
    depth = 0  # indentation depth
    skipping = False  # inside a module-level import statement
    prev_sig = tk.NEWLINE  # previous significant token type (docstring detection)
    prev_text = ""
    for t in _tokens(text):
        if t.type in SKIP_TYPES:
            continue
        if t.type == tk.INDENT:
            depth += 1
        elif t.type == tk.DEDENT:
            depth -= 1
        if skipping:
            if t.type == tk.NEWLINE:
                skipping = False
                line_start = True
            continue
        if line_start and depth == 0 and t.type == tk.NAME and t.string in ("import", "from"):
            skipping = True
            continue
        # a docstring: a string statement opening a module, class or function body
        if (
            t.type == tk.STRING
            and line_start
            and (prev_sig == tk.INDENT or (prev_sig == tk.NEWLINE and prev_text == ""))
        ):
            skipping = True  # drop it through its NEWLINE
            continue
        line_start = t.type in (tk.NEWLINE, tk.INDENT, tk.DEDENT)
        if t.type not in (tk.INDENT, tk.DEDENT):
            prev_sig, prev_text = t.type, t.string
        elif t.type == tk.INDENT:
            prev_sig, prev_text = tk.INDENT, ""
        norm.append(_norm(t, mode))
        lines.append(t.start[0])
    return norm, lines


def _tokens(text: str):
    """``tokenize`` tokens with each f-string as ONE ``STRING`` token, as Python 3.11 emits it.

    From 3.12 an f-string is split into FSTRING_START / MIDDLE / END around its replacement
    fields, so the same file would give different token runs (and different clone hashes) on
    different interpreters, and a baseline written on one would fail on another.
    """
    fstart = getattr(tk, "FSTRING_START", None)
    fend = getattr(tk, "FSTRING_END", None)
    if fstart is None:
        yield from tokenize.generate_tokens(io.StringIO(text).readline)
        return
    lines = text.splitlines(keepends=True)
    depth = 0
    begin = None
    for t in tokenize.generate_tokens(io.StringIO(text).readline):
        if t.type == fstart:
            if depth == 0:
                begin = t
            depth += 1
            continue
        if depth:
            if t.type == fend:
                depth -= 1
                if depth == 0:
                    (r0, c0), (r1, c1) = begin.start, t.end
                    if r0 == r1:
                        src = lines[r0 - 1][c0:c1]
                    else:
                        src = lines[r0 - 1][c0:] + "".join(lines[r0 : r1 - 1]) + lines[r1 - 1][:c1]
                    yield tokenize.TokenInfo(tk.STRING, src, begin.start, t.end, begin.line)
            continue
        yield t


def _norm(t: tokenize.TokenInfo, mode: str) -> str:
    if t.type == tk.NEWLINE:
        return ";"
    if t.type == tk.INDENT:
        return "{"
    if t.type == tk.DEDENT:
        return "}"
    if mode == "exact":
        return t.string
    if t.type == tk.NAME:
        return t.string if keyword.iskeyword(t.string) or t.string in ("self", "cls") else "$id"
    if t.type == tk.STRING or t.type in FSTRING_PARTS:
        return "$str"
    if t.type == tk.NUMBER:
        return "$num"
    return t.string


def load_sources(root: Path, rels: list[str], mode: str) -> tuple[list[Source], list[str]]:
    srcs: list[Source] = []
    errors: list[str] = []
    for rel in rels:
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{rel}: unreadable ({exc.__class__.__name__})")
            continue
        if any(m in "\n".join(text.splitlines()[:5]) for m in GENERATED_MARKS):
            continue
        try:
            norm, lines = tokens_of(text, mode)
        except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
            errors.append(f"{rel}: cannot tokenise ({exc.__class__.__name__})")
            continue
        srcs.append(Source(rel, norm, lines, text.count("\n") + (not text.endswith("\n"))))
    return srcs, errors


# ---------------------------------------------------------------- clone detection


def find_clones(srcs: list[Source], min_tokens: int, min_lines: int) -> list[Clone]:
    w = min_tokens
    intern: dict[str, int] = {}
    ids = [[intern.setdefault(s, len(intern)) for s in src.norm] for src in srcs]
    index: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for f, seq in enumerate(ids):
        for i in range(len(seq) - w + 1):
            index[hash(tuple(seq[i : i + w]))].append((f, i))

    # every location of a repeated window pairs with the first one (k copies -> k-1 pairs);
    # windows of one pair that follow each other on the same diagonal merge into one clone
    diag: dict[tuple[int, int, int], list[int]] = defaultdict(list)
    for locs in index.values():
        if len(locs) < 2:
            continue
        fa, ia = locs[0]
        for fb, ib in locs[1:]:
            if fa == fb and ib - ia < w:
                continue  # overlapping self-match (a run of near-identical lines)
            diag[(fa, fb, ia - ib)].append(ia)

    raw: list[tuple[int, int, int, int, int]] = []  # (fa, sa, fb, sb, length)
    for (fa, fb, off), starts in diag.items():
        starts.sort()
        run_start = prev = starts[0]
        for s in [*starts[1:], None]:
            if s is not None and s == prev + 1:
                prev = s
                continue
            length = prev - run_start + w
            sa, sb = run_start, run_start - off
            if ids[fa][sa : sa + length] == ids[fb][sb : sb + length]:  # no hash collision
                raw.append((fa, sa, fb, sb, length))
            if s is not None:
                run_start = prev = s

    # drop a pair that lies inside a longer pair of the same two files
    raw.sort(key=lambda r: -r[4])
    kept: list[tuple[int, int, int, int, int]] = []
    for r in raw:
        fa, sa, fb, sb, n = r
        if any(
            k[0] == fa
            and k[2] == fb
            and k[1] <= sa
            and sa + n <= k[1] + k[4]
            and k[3] <= sb
            and sb + n <= k[3] + k[4]
            for k in kept
        ):
            continue
        kept.append(r)

    clones: list[Clone] = []
    seen: set[tuple] = set()
    for fa, sa, fb, sb, n in kept:
        A, B = srcs[fa], srcs[fb]
        sa, sb, n = _whole_statements(A.norm, sa, B.norm, sb, n)
        if n < min_tokens:
            continue
        a = (A.path, A.lines[sa], A.lines[sa + n - 1])
        b = (B.path, B.lines[sb], B.lines[sb + n - 1])
        if a[2] - a[1] + 1 < min_lines or b[2] - b[1] + 1 < min_lines:
            continue
        a, b = sorted((a, b))
        if (a, b) in seen:
            continue
        seen.add((a, b))
        toks = A.norm[sa : sa + n]
        clones.append(Clone(a, b, toks, content_key(toks), fingerprints(toks, min_tokens)))
    clones.sort(key=lambda c: (-c.size, c.a, c.b))
    return clones


def _whole_statements(na: list[str], sa: int, nb: list[str], sb: int, n: int):
    """Trim a matched run to whole logical lines: start where a statement starts in both copies,
    end at a statement's NEWLINE. The key then never depends on a neighbour that happens to end
    or begin with the same tokens (``= 2 ;`` before both copies), so editing it cannot churn it."""

    def starts(seq: list[str], i: int) -> bool:
        return (i == 0 or seq[i - 1] in STRUCTURE) and seq[i] not in STRUCTURE

    lo, hi = 0, n
    while lo < hi and not (starts(na, sa + lo) and starts(nb, sb + lo)):
        lo += 1
    while hi > lo and na[sa + hi - 1] != ";":
        hi -= 1
    return sa + lo, sb + lo, hi - lo


def content_key(toks: list[str]) -> str:
    return hashlib.sha256("\x1f".join(toks).encode()).hexdigest()[:16]


def fingerprints(toks: list[str], min_tokens: int) -> frozenset:
    """Winnowed k-gram hashes: any run of >= min_tokens tokens of this clone keeps at least one,
    and a sub-run's fingerprints are a subset of the whole clone's."""
    k = max(1, min_tokens // 2)
    win = max(1, min_tokens - k + 1)
    grams = [
        hashlib.blake2b("\x1f".join(toks[i : i + k]).encode(), digest_size=5).hexdigest()
        for i in range(len(toks) - k + 1)
    ]
    out = set()
    for i in range(max(1, len(grams) - win + 1)):
        window = grams[i : i + win]
        if window:
            out.add(min(window))
    return frozenset(out)


def duplicated_lines(clones: list[Clone]) -> int:
    seen: set[tuple[str, int]] = set()
    for c in clones:
        for p, s, e in (c.a, c.b):
            seen.update((p, n) for n in range(s, e + 1))
    return len(seen)


# ---------------------------------------------------------------- baseline


class BaselineError(ValueError):
    pass


def build_baseline(clones, total_lines, params, previous=None, reason=None) -> dict:
    entries: dict[str, dict] = {}
    for c in clones:
        e = entries.setdefault(
            c.key,
            {
                "tokens": c.size,
                "lines": c.a[2] - c.a[1] + 1,
                "count": 0,
                "files": set(),
                "fp": c.fps,
            },
        )
        e["count"] += 1
        e["files"].update((c.a[0], c.b[0]))
    dup = duplicated_lines(clones)
    doc = {
        "schema": SCHEMA,
        "params": params,
        "summary": {
            "clones": len(clones),
            "duplicated_lines": dup,
            "total_lines": total_lines,
            "duplicated_percent": round(100 * dup / total_lines, 2) if total_lines else 0.0,
        },
        "increases": list((previous or {}).get("increases", [])),
        "clones": {
            k: {
                "tokens": e["tokens"],
                "lines": e["lines"],
                "count": e["count"],
                "files": sorted(e["files"]),
                "fingerprints": sorted(e["fp"]),
            }
            for k, e in sorted(entries.items())
        },
    }
    if reason:
        before = (previous or {}).get("summary", {}).get("duplicated_lines", 0)
        doc["increases"].append({"reason": reason, "from": before, "to": dup})
    return doc


def load_baseline(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{path}: not JSON ({exc})") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise BaselineError(f"{path}: not a schema {SCHEMA} dup_check baseline")
    for key in ("params", "summary", "clones"):
        if not isinstance(doc.get(key), dict):
            raise BaselineError(f"{path}: '{key}' must be an object")
    for k, e in doc["clones"].items():
        if not (isinstance(e, dict) and isinstance(e.get("count"), int)):
            raise BaselineError(f"{path}: clone {k} needs an integer 'count'")
        if not (isinstance(e.get("tokens"), int) and isinstance(e.get("fingerprints"), list)):
            raise BaselineError(f"{path}: clone {k} needs 'tokens' and 'fingerprints'")
    return doc


def compare(clones: list[Clone], baseline: dict) -> tuple[list[Clone], list[str], int]:
    """(clones the baseline does not cover, stale baseline keys, clones covered as a shrunk entry).

    An exact key match is covered up to the entry's ``count`` (one more copy is a new clone).
    Otherwise a clone no longer than an entry whose fingerprints are a subset of the entry's is
    that entry shrunk: one copy was edited, so less of it is duplicated. Pieces of a clone split
    by an edit in its middle stay within the entry's files and are all covered; a piece in another
    file is a copy and needs the entry's budget."""
    entries = baseline["clones"]
    budget = {k: e["count"] for k, e in entries.items()}
    used: dict[str, int] = defaultdict(int)
    fps = {k: set(e["fingerprints"]) for k, e in entries.items()}
    new: list[Clone] = []
    rest: list[Clone] = []
    for c in clones:
        if c.key in budget and used[c.key] < budget[c.key]:
            used[c.key] += 1
        else:
            rest.append(c)
    shrunk = 0
    for c in rest:
        files = {c.a[0], c.b[0]}
        cand = [
            k
            for k, e in entries.items()
            if c.size <= e["tokens"]
            and c.fps
            and c.fps <= fps[k]
            and (files <= set(e.get("files", ())) or used[k] < budget[k])
        ]
        if cand:
            used[min(cand, key=lambda k: entries[k]["tokens"])] += 1
            shrunk += 1
        else:
            new.append(c)
    stale = sorted(k for k in budget if used[k] == 0)
    return new, stale, shrunk


# ---------------------------------------------------------------- CLI


def scan(root: Path, params: dict):
    srcs, errors = load_sources(root, tracked_python(root), params["mode"])
    clones = find_clones(srcs, params["min_tokens"], params["min_lines"])
    return clones, sum(s.nlines for s in srcs), len(srcs), errors


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--baseline", help=f"default: <root>/{DEFAULT_BASELINE}")
    ap.add_argument("--mode", choices=("exact", "normalised"))
    ap.add_argument("--min-tokens", type=int)
    ap.add_argument("--min-lines", type=int)
    ap.add_argument("--update-baseline", action="store_true", help="rewrite the baseline")
    ap.add_argument("--allow-increase", metavar="REASON", help="let an update raise the total")
    ap.add_argument("--list", action="store_true", help="print every clone, baselined or not")
    ap.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.allow_increase is not None and not (
        args.update_baseline and args.allow_increase.strip()
    ):
        print("dup_check: --allow-increase needs --update-baseline and a reason", file=err)
        return 2
    root = Path(args.root).resolve()
    bpath = Path(args.baseline) if args.baseline else root / DEFAULT_BASELINE
    try:
        baseline = load_baseline(bpath)
    except BaselineError as exc:
        print(f"dup_check: bad baseline: {exc}", file=err)
        return 2

    asked = {"mode": args.mode, "min_tokens": args.min_tokens, "min_lines": args.min_lines}
    params = {
        k: asked[k] if asked[k] is not None else (baseline or {}).get("params", DEFAULTS)[k]
        for k in DEFAULTS
    }
    if params["min_tokens"] < 10 or params["min_lines"] < 1:
        print("dup_check: --min-tokens must be >= 10 and --min-lines >= 1", file=err)
        return 2
    changed = baseline is not None and params != baseline["params"]

    try:
        clones, total, nfiles, errors = scan(root, params)
    except SystemExit as exc:
        print(exc, file=err)
        return 2
    for e in errors:
        print(f"dup_check: {e}", file=err)
    dup = duplicated_lines(clones)
    pct = round(100 * dup / total, 2) if total else 0.0
    summary = f"{len(clones)} clone(s), {dup}/{total} lines duplicated ({pct}%), {nfiles} files"

    if args.list:
        for c in clones:
            print(f"{c.size:5d} tokens  {c.where()}  [{c.key}]", file=out)

    if args.update_baseline:
        before = (baseline or {}).get("summary", {}).get("duplicated_lines")
        if baseline is not None and not args.allow_increase and (changed or dup > before):
            why = (
                f"parameters change {baseline['params']} -> {params}"
                if changed
                else f"duplicated lines would rise {before} -> {dup}"
            )
            print(f"dup_check: refusing to update the baseline: {why}", file=err)
            print("dup_check: remove the duplication, or pass --allow-increase REASON", file=err)
            return 2
        doc = build_baseline(clones, total, params, baseline, args.allow_increase)
        bpath.parent.mkdir(parents=True, exist_ok=True)
        bpath.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n", encoding="utf-8")
        print(f"dup_check: baseline written to {bpath}: {summary}", file=out)
        return 1 if errors else 0

    if baseline is None:
        print(f"dup_check: no baseline at {bpath}; every clone is new", file=err)
        baseline = {"params": params, "summary": {}, "clones": {}}
    elif changed:
        print(
            f"dup_check: parameters {params} differ from the baseline's {baseline['params']}; "
            "a check must use the baseline's",
            file=err,
        )
        return 2
    new, stale, shrunk = compare(clones, baseline)
    if args.json:
        doc = {
            "summary": {"clones": len(clones), "duplicated_lines": dup, "total_lines": total},
            "new": [{"a": c.a, "b": c.b, "tokens": c.size, "key": c.key} for c in new],
            "stale": stale,
        }
        print(json.dumps(doc, indent=2), file=out)
    else:
        for c in new:
            print(f"dup_check: new clone ({c.size} tokens): {c.where()}", file=err)
        for k in stale:
            e = baseline["clones"][k]
            print(
                f"dup_check: stale baseline entry {k} ({', '.join(e['files'])}): the clone is gone; "
                "run `python tools/dup_check.py --update-baseline` so the baseline shrinks",
                file=err,
            )
        if shrunk:
            print(
                f"dup_check: {shrunk} baselined clone(s) shrank; --update-baseline records it",
                file=out,
            )
        print(f"dup_check: {len(new)} new, {len(stale)} stale; {summary}", file=out)
    return 1 if new or stale or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
