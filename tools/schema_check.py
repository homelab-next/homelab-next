#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: schema-check
#   kind: check
#   purpose: Fail when a schema is invalid, lacks an example or a negative, or breaks its frozen baseline.
#   owner: maintainers
#   trigger: [ci:ci/schemas, code:homelabnext/cli.py, make:schemas]
#   invariant: [Q-10]
#   inputs: schemas/ (with examples/, negative/ and _frozen/)
#   outputs: one line per problem and a summary; --freeze writes missing baselines
#   exit:
#     "0": no errors
#     "1": errors
"""Schema contract checker.

For every schema under ``schemas/<dir>/`` (top level only):

1. it is valid JSON Schema 2020-12 and carries an ``$id`` of the form
   ``https://schemas.example.internal/homelabnext/<name>/<major>.<minor>``;
2. it has >= 1 example (``examples/<stem>.<label>.<ext>``) that validates;
3. it has >= 1 negative (``negative/<stem>.<label>.<ext>``) that is *rejected*
   (schemas marked ``"x-defs-only": true`` hold only ``$defs`` and are exempt from 2 and 3);
4. every example is free of non-documentation IP literals and
   ``viking://`` URIs;
5. the schema is an *additive* evolution of its frozen baseline
   (``schemas/_frozen/<major>.<minor-at-freeze>/...``) unless the major version
   was bumped.

Instances may be ``.json``, ``.yaml``/``.yml`` or ``.md`` (YAML frontmatter).

Semantic helpers that JSON Schema cannot express live here too:
:func:`check_note_filename`, :func:`check_kanban_board`, :func:`check_profile_ceiling`.

Usage: ``python tools/schema_check.py [--root DIR] [--freeze] [--strict]``
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homelabnext.ids.lint import scan_document  # noqa: E402

ID_RE = re.compile(r"^https://schemas\.example\.internal/homelabnext/([a-z0-9_./-]+)/(\d+)\.(\d+)$")
INSTANCE_EXTS = {".json", ".yaml", ".yml", ".md"}
SKIP_DIRS = {"examples", "negative", "_frozen"}


@dataclass(frozen=True)
class Problem:
    where: str
    message: str
    severity: str = "error"  # error | warning

    def __str__(self) -> str:
        return f"{self.severity.upper()} {self.where}: {self.message}"


# ---------------------------------------------------------------- loading
class _StrLoader(yaml.SafeLoader):
    """SafeLoader that keeps timestamps as strings (JSON has no timestamp type)."""


_StrLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load_instance(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    if path.suffix == ".md":
        m = re.match(r"\A---\n(.*?)\n---\s*(?:\n|\Z)", text, re.S)
        if not m:
            raise ValueError(f"{path}: no YAML frontmatter")
        return yaml.load(m.group(1), Loader=_StrLoader)
    return yaml.load(text, Loader=_StrLoader)


def split_markdown(text: str) -> tuple[dict, str]:
    m = re.match(r"\A---\n(.*?)\n---\s*(?:\n|\Z)", text, re.S)
    if not m:
        raise ValueError("no YAML frontmatter")
    return yaml.load(m.group(1), Loader=_StrLoader), text[m.end() :]


def schema_files(root: Path, dirs: Iterable[str] | None = None) -> list[Path]:
    base = root / "schemas"
    out: list[Path] = []
    for d in sorted(p for p in base.iterdir() if p.is_dir() and p.name not in SKIP_DIRS):
        if dirs is not None and d.name not in dirs:
            continue
        out += sorted(f for f in d.glob("*.json"))
    return out


def stem_of(schema_path: Path) -> str:
    n = schema_path.name
    return n[: -len(".schema.json")] if n.endswith(".schema.json") else n[: -len(".json")]


def build_registry(root: Path) -> Registry:
    reg: Registry = Registry()
    for p in schema_files(root):
        doc = json.loads(p.read_text(encoding="utf-8"))
        if "$id" in doc:
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    return reg


def validator_for(schema: dict, registry: Registry) -> Draft202012Validator:
    return Draft202012Validator(schema, registry=registry)


def errors_for(schema: dict, instance: Any, registry: Registry) -> list[str]:
    v = validator_for(schema, registry)
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
        for e in sorted(v.iter_errors(instance), key=lambda e: list(map(str, e.absolute_path)))
    ]


def instances_for(schema_path: Path, kind: str) -> list[Path]:
    """Files ``<kind>/<stem>.<label>.<ext>`` belonging to exactly this schema."""
    d = schema_path.parent / kind
    stem = stem_of(schema_path)
    if not d.is_dir():
        return []
    return sorted(
        f for f in d.iterdir() if f.suffix in INSTANCE_EXTS and f.stem.rsplit(".", 1)[0] == stem
    )


# ---------------------------------------------------------------- additive evolution
_ANNOTATIONS = {
    "$schema",
    "$id",
    "$comment",
    "title",
    "description",
    "examples",
    "default",
    "deprecated",
    "readOnly",
    "writeOnly",
    "x-defs-only",
    "$anchor",
}
_NUM_LOWER = {
    "minimum",
    "exclusiveMinimum",
    "minLength",
    "minItems",
    "minProperties",
}  # new must be <= old
_NUM_UPPER = {
    "maximum",
    "exclusiveMaximum",
    "maxLength",
    "maxItems",
    "maxProperties",
}  # new must be >= old
_TIGHTENING_IF_NEW = (
    _NUM_LOWER
    | _NUM_UPPER
    | {
        "pattern",
        "enum",
        "const",
        "required",
        "format",
        "uniqueItems",
        "propertyNames",
        "not",
        "patternProperties",
        "dependentRequired",
        "minContains",
        "maxContains",
        "unevaluatedProperties",
    }
)


def _newline_guard_only(old: str, new: str) -> bool:
    """``new`` is ``old`` with ``(?!\\n)`` appended to its closing ``$``: the same language.

    JSON Schema patterns are ECMA-262 regular expressions, where ``$`` (no multiline flag)
    matches only at the end of the input, so the lookahead after it is always true.  Python's
    ``re``, which the repository's validators use, also lets ``$`` match before a trailing
    newline; the guard makes Python agree with the contract, it does not change the contract.
    """
    if not (isinstance(old, str) and isinstance(new, str) and new == old + "(?!\\n)"):
        return False
    body = old[:-1]
    return old.endswith("$") and (len(body) - len(body.rstrip("\\"))) % 2 == 0


def _as_types(t: Any) -> set[str]:
    return set(t) if isinstance(t, list) else {t}


def _widened_to_any_of(old: Any, new: Any) -> bool:
    """``new`` is ``{"anyOf": [..., B, ...]}`` (plus annotations only) where ``old`` is not an
    ``anyOf`` and evolves additively into the branch ``B``: whatever ``old`` accepted, ``B``
    accepts, so the alternatives only widen it (for example a name that may now also be an
    object)."""
    if not isinstance(new, dict) or "anyOf" in old or not isinstance(new.get("anyOf"), list):
        return False
    if any(k not in _ANNOTATIONS for k in new if k != "anyOf"):
        return False
    return any(is_additive(old, branch) == [] for branch in new["anyOf"])


def is_additive(old: Any, new: Any, path: str = "$") -> list[str]:
    """Return reasons ``new`` is NOT an additive evolution of ``old`` (empty = compatible).

    Additive means every document valid under ``old`` stays valid under ``new``
    (checked structurally and conservatively): properties/enum members/types may
    be added; nothing may be removed, required, or tightened.
    """
    if isinstance(old, bool) or isinstance(new, bool):
        return [] if (new is True or old == new) else [f"{path}: schema became {new}"]
    if _widened_to_any_of(old, new):
        return []
    out: list[str] = []
    for key, ov in old.items():
        if key in _ANNOTATIONS:
            continue
        if key not in new:
            if key in {"properties", "$defs", "definitions"}:
                out.append(f"{path}: '{key}' removed")
            elif (  # noqa: SIM102
                key
                in {
                    "required",
                    "enum",
                    "const",
                    "type",
                    "pattern",
                    "additionalProperties",
                    "items",
                    "allOf",
                    "anyOf",
                    "oneOf",
                    "$ref",
                    "if",
                    "then",
                    "else",
                    "propertyNames",
                }
                | _NUM_LOWER
                | _NUM_UPPER
            ):
                # removing a constraint loosens (fine) except these structural ones where removal drops information we compare on
                if key in {"$ref", "allOf", "anyOf", "oneOf", "if", "then", "else"}:
                    out.append(f"{path}: '{key}' removed")
            continue
        nv = new[key]
        p = f"{path}.{key}"
        if key == "type":
            if not _as_types(ov) <= _as_types(nv):
                out.append(f"{p}: type narrowed {ov} -> {nv}")
        elif key == "required":
            added = set(nv) - set(ov)
            if added:
                out.append(f"{p}: newly required {sorted(added)}")
        elif key == "enum":
            lost = [x for x in ov if x not in nv]
            if lost:
                out.append(f"{p}: enum values removed {lost}")
        elif key == "const":
            if ov != nv:
                out.append(f"{p}: const changed {ov!r} -> {nv!r}")
        elif key == "pattern":
            if ov != nv and not _newline_guard_only(ov, nv):
                out.append(f"{p}: pattern changed (cannot prove compatible)")
        elif key in _NUM_LOWER:
            if nv > ov:
                out.append(f"{p}: raised {ov} -> {nv}")
        elif key in _NUM_UPPER:
            if nv < ov:
                out.append(f"{p}: lowered {ov} -> {nv}")
        elif key == "additionalProperties":
            if ov is not False and nv is False:
                out.append(f"{p}: additionalProperties tightened to false")
            elif isinstance(ov, dict) and isinstance(nv, dict):
                out += is_additive(ov, nv, p)
        elif key in {"properties", "$defs", "definitions", "patternProperties"}:
            for name, osub in ov.items():
                if name not in nv:
                    out.append(f"{p}.{name}: removed")
                else:
                    out += is_additive(osub, nv[name], f"{p}.{name}")
        elif key in {"items", "contains", "not", "if", "then", "else", "propertyNames"}:
            if isinstance(ov, (dict, bool)):
                out += is_additive(ov, nv, p)
        elif key in {"allOf", "anyOf", "oneOf"}:
            if len(ov) != len(nv):
                out.append(f"{p}: {key} length changed {len(ov)} -> {len(nv)}")
            else:
                for i, (a, b) in enumerate(zip(ov, nv, strict=False)):
                    out += is_additive(a, b, f"{p}[{i}]")
        elif key == "$ref":
            if ov != nv:
                out.append(f"{p}: $ref changed {ov} -> {nv}")
        elif ov != nv and key not in _ANNOTATIONS:
            out.append(f"{p}: changed {ov!r} -> {nv!r}")
    for key in new:
        if key in old or key in _ANNOTATIONS:
            continue
        if key in _TIGHTENING_IF_NEW:
            out.append(f"{path}.{key}: new constraint '{key}' added (tightens)")
        elif key == "additionalProperties" and new[key] is False:
            out.append(f"{path}.additionalProperties: tightened to false")
        elif key in {"allOf", "if", "unevaluatedItems"}:
            out.append(f"{path}.{key}: new constraint '{key}' added (tightens)")
        elif key == "type":
            out.append(f"{path}.type: type constraint added")
    return out


def parse_id(schema: dict) -> tuple[str, int, int] | None:
    m = ID_RE.match(schema.get("$id", ""))
    return (m.group(1), int(m.group(2)), int(m.group(3))) if m else None


def frozen_path(root: Path, schema_path: Path, major: int, minor: int) -> Path:
    return (
        root
        / "schemas"
        / "_frozen"
        / f"{major}.{minor}"
        / schema_path.parent.name
        / schema_path.name
    )


def freeze(root: Path) -> list[Path]:
    """Copy every schema without a baseline for its (major, minor) into ``_frozen``."""
    written = []
    for p in schema_files(root):
        s = json.loads(p.read_text(encoding="utf-8"))
        pid = parse_id(s)
        if not pid:
            continue
        dest = frozen_path(root, p, pid[1], pid[2])
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, dest)
            written.append(dest)
    return written


def baselines(root: Path, schema_path: Path) -> list[tuple[int, int, Path]]:
    out = []
    base = root / "schemas" / "_frozen"
    if base.is_dir():
        for vd in base.iterdir():
            f = vd / schema_path.parent.name / schema_path.name
            if f.is_file() and re.fullmatch(r"\d+\.\d+", vd.name):
                a, b = vd.name.split(".")
                out.append((int(a), int(b), f))
    return sorted(out)


# ---------------------------------------------------------------- repo check
def check_schema(
    root: Path, schema_path: Path, registry: Registry, strict: bool = False
) -> list[Problem]:
    rel = schema_path.relative_to(root).as_posix()
    probs: list[Problem] = []
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        return [Problem(rel, f"invalid JSON Schema: {exc}")]
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        probs.append(Problem(rel, "$schema must be the 2020-12 dialect"))
    pid = parse_id(schema)
    if not pid:
        probs.append(Problem(rel, f"$id {schema.get('$id')!r} does not match {ID_RE.pattern}"))
    exs = instances_for(schema_path, "examples")
    negs = instances_for(schema_path, "negative")
    if not exs and not schema.get("x-defs-only"):
        probs.append(Problem(rel, "no example (examples/<stem>.<label>.<ext>)"))
    if not negs and not schema.get("x-defs-only"):
        probs.append(Problem(rel, "no negative (negative/<stem>.<label>.<ext>)"))
    for f in exs:
        try:
            errs = errors_for(schema, load_instance(f), registry)
        except Exception as exc:
            errs = [f"unreadable: {exc}"]
        for e in errs:
            probs.append(Problem(f.relative_to(root).as_posix(), f"example rejected: {e}"))
    for f in negs:
        try:
            errs = errors_for(schema, load_instance(f), registry)
        except Exception as exc:
            probs.append(Problem(f.relative_to(root).as_posix(), f"negative unreadable: {exc}"))
            continue
        if not errs:
            probs.append(
                Problem(f.relative_to(root).as_posix(), "negative was ACCEPTED by the schema")
            )
    for f in exs:
        try:
            doc = load_instance(f)
        except Exception:
            continue
        for v in scan_document(doc):
            probs.append(Problem(f.relative_to(root).as_posix(), f"lint {v}"))
    if pid:
        bl = baselines(root, schema_path)
        same_major = [b for b in bl if b[0] == pid[1]]
        if not same_major:
            probs.append(
                Problem(rel, "no frozen baseline (run --freeze)", "error" if strict else "warning")
            )
        for _, _, bf in same_major:
            old = json.loads(bf.read_text(encoding="utf-8"))
            for reason in is_additive(old, schema):
                probs.append(Problem(rel, f"not additive vs {bf.parent.parent.name}: {reason}"))
    return probs


def check_repo(
    root: Path = REPO_ROOT,
    dirs: Iterable[str] | None = None,
    strict: bool = False,
    only: Iterable[str] | None = None,
) -> list[Problem]:
    registry = build_registry(root)
    probs: list[Problem] = []
    for p in schema_files(root, dirs):
        if only is not None and p.relative_to(root / "schemas").as_posix() not in set(only):
            continue
        probs += check_schema(root, p, registry, strict)
    return probs


# ---------------------------------------------------------------- semantic checks
NOTE_FILENAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\.md$")


def check_note_filename(filename: str, frontmatter: dict) -> list[str]:
    """Filename must be ``<date>-<requesting-agent>-<slug>.md`` and agree with the frontmatter."""
    m = NOTE_FILENAME_RE.match(filename)
    if not m:
        return [f"filename {filename!r} is not <YYYY-MM-DD>-<agent>-<slug>.md"]
    date, rest = m.groups()
    out = []
    created = str(frontmatter.get("created", ""))
    if created[:10] != date:
        out.append(f"filename date {date} != created {created[:10]!r}")
    agent = str(frontmatter.get("requesting_agent", "")).partition(":")[2]
    if not agent or not (rest == agent or rest.startswith(agent + "-")) or rest == agent:
        out.append(
            f"filename must be '{date}-{agent}-<slug>' (requesting_agent {frontmatter.get('requesting_agent')!r})"
        )
    return out


def check_kanban_board(items: list[dict]) -> list[str]:
    """Cross-card rules the generator enforces fatally."""
    out: list[str] = []
    ids = [i["id"] for i in items if "id" in i and not i["id"].endswith("NEW")]
    for dup in sorted({x for x in ids if ids.count(x) > 1}):
        out.append(f"duplicate id {dup}")
    projects = {i["id"]: i for i in items if re.fullmatch(r"PRJ-\d{3}", i.get("id", ""))}
    for i in items:
        iid = i.get("id", "")
        m = re.fullmatch(r"(PRJ-\d{3})\.(\d+)", iid)
        if m:
            proj = projects.get(m.group(1))
            if not proj:
                out.append(f"step card {iid} references missing project {m.group(1)}")
                continue
            step = next((s for s in proj.get("steps", []) if s["n"] == int(m.group(2))), None)
            if step is None:
                out.append(f"step card {iid} references missing step {m.group(2)}")
            elif step["status"] != "open" and i.get("column") != "done":
                out.append(f"step card {iid} references a step that is already done")
    for pid, p in projects.items():
        steps = p.get("steps", [])
        if p.get("column") == "partial" and steps and all(s["status"] == "done" for s in steps):
            out.append(f"project {pid} has all steps done but sits in partial")
    return out


def check_profile_ceiling(profile: dict) -> list[str]:
    extra = sorted(set(profile.get("mcp", [])) - set(profile.get("mcp_ceiling", [])))
    return [f"mcp servers outside ceiling: {extra}"] if extra else []


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    ap.add_argument(
        "--freeze", action="store_true", help="write missing frozen baselines, then check"
    )
    ap.add_argument("--strict", action="store_true", help="missing baseline is an error")
    ap.add_argument("--dir", action="append", help="limit to schemas/<dir> (repeatable)")
    args = ap.parse_args(argv)
    if args.freeze:
        for f in freeze(args.root):
            print(f"froze {f.relative_to(args.root)}")
    probs = check_repo(args.root, args.dir, args.strict)
    for p in probs:
        print(p)
    errors = [p for p in probs if p.severity == "error"]
    n = len(schema_files(args.root, args.dir))
    print(f"schema_check: {n} schemas, {len(errors)} errors, {len(probs) - len(errors)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
