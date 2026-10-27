# SPDX-License-Identifier: Apache-2.0
"""The per-field review tier of an in-tree module manifest (ADR-0027 follow-up 4; docs/modules.md,
"Trust tiers").

A change to a manifest needs a **human approve** when it touches what a module may do with trust
(``credentials``, ``control_plane``, ``egress``, an agent's ``needs`` (its data grants), a
privileged slot it provides, requires or prefers) or what it is (``id``, ``kind``, ``origin``);
any other change needs only the **owner**.  :func:`classify` compares two versions of one
manifest field by field and fails closed: a new or removed manifest, one that cannot be read, a
top-level or block key the module schema does not define, and a capability entry that names no
capability all count as human-approve, and with no slot registry every slot or capability change
does.

:func:`changed_manifests` lists the manifests a commit range changed (``git diff`` against a base
commit), and :func:`codeowners_for` reads which CODEOWNERS rule covers a path.  This module
classifies; the approval itself is the pull request's code-owner review (``.github/CODEOWNERS``,
"Require review from Code Owners"), which ``hnx modules review-tier`` checks covers every manifest
with a human-approve change.  Nothing here authenticates a reviewer.
"""

from __future__ import annotations

import fnmatch
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from homelabnext._yaml import UniqueKeyLoader

__all__ = [
    "HUMAN",
    "OWNER",
    "Change",
    "changed_manifests",
    "classify",
    "codeowners_for",
    "load_codeowners",
    "privileged_slots",
    "schema_keys",
    "tier_of",
]

HUMAN = "human-approve"
OWNER = "owner"
#: top-level fields whose change always needs a human approve: what the module may do with trust,
#: and what it is
HUMAN_FIELDS = ("credentials", "control_plane", "egress", "id", "kind", "origin")
#: the manifest paths the tier covers, relative to the repository root
MANIFEST_GLOBS = ("modules/*/module.yml", "examples/modules/*/module.yml")
#: where GitHub reads CODEOWNERS from, first found wins
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


@dataclass(frozen=True)
class Change:
    field: str  # a dotted path: credentials, provides.slots.secrets, contributes.agents.x.needs
    tier: str  # HUMAN or OWNER
    why: str


def schema_keys(schema: dict) -> dict[str, set[str]]:
    """The keys the module schema defines: ``""`` for the top level, and per block
    (``provides``, ``requires``, ``prefers``)."""
    props = schema.get("properties") or {}
    out = {"": set(props)}
    for block in ("provides", "requires", "prefers"):
        node = props.get(block) or {}
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            node = (schema.get("$defs") or {}).get(ref.rsplit("/", 1)[-1]) or {}
        out[block] = set(node.get("properties") or {})
    return out


def privileged_slots(slot_registry: Any) -> set[str] | None:
    """``cap:<slot>`` for every slot the registry marks ``privileged``, or None when the registry
    cannot be read (every slot change is then human-approve)."""
    slots = slot_registry.get("slots") if isinstance(slot_registry, dict) else None
    if not isinstance(slots, dict):
        return None
    return {f"cap:{s}" for s, d in slots.items() if isinstance(d, dict) and d.get("privileged")}


def _same(a: Any, b: Any) -> bool:
    return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)


def _by(items: Any, key) -> dict | None:
    """A list of mappings indexed by ``key(item)``, or None when it is not one (fail closed)."""
    if items is None:
        return {}
    if not isinstance(items, list):
        return None
    out: dict = {}
    for it in items:
        k = key(it) if isinstance(it, dict) else None
        if k is None or k in out:
            return None
        out[k] = it
    return out


def _cap_entry_key(e: dict):
    cap = e.get("cap")
    return (cap, e.get("instance")) if isinstance(cap, str) else None


def _capabilities(block: str, old: Any, new: Any, priv: set[str] | None) -> list[Change]:
    field = f"{block}.capabilities"
    o, n = _by(old, _cap_entry_key), _by(new, _cap_entry_key)
    if o is None or n is None:
        return [Change(field, HUMAN, "not a list of capability entries (fail closed)")]
    out = []
    for k in sorted({*o, *n}, key=str):
        if _same(o.get(k), n.get(k)):
            continue
        cap, inst = k
        name = f"{field}.{cap}" + (f"[{inst}]" if inst else "")
        if priv is None:
            out.append(
                Change(name, HUMAN, "no slot registry to tell a privileged slot (fail closed)")
            )
        elif cap in priv:
            out.append(Change(name, HUMAN, f"{cap} is a privileged slot"))
        else:
            out.append(Change(name, OWNER, "a capability entry"))
    return out


def _slots(old: Any, new: Any, priv: set[str] | None) -> list[Change]:
    if not isinstance(old or {}, dict) or not isinstance(new or {}, dict):
        return [Change("provides.slots", HUMAN, "not a mapping of slots (fail closed)")]
    o, n = old or {}, new or {}
    out = []
    for s in sorted({*o, *n}, key=str):
        if _same(o.get(s), n.get(s)):
            continue
        name = f"provides.slots.{s}"
        if priv is None:
            out.append(
                Change(name, HUMAN, "no slot registry to tell a privileged slot (fail closed)")
            )
        elif f"cap:{s}" in priv:
            out.append(Change(name, HUMAN, f"cap:{s} is a privileged slot"))
        else:
            out.append(Change(name, OWNER, "a provided slot"))
    return out


def _block(block: str, old: Any, new: Any, keys: set[str], priv: set[str] | None) -> list[Change]:
    if not isinstance(old or {}, dict) or not isinstance(new or {}, dict):
        return [Change(block, HUMAN, "not a mapping (fail closed)")]
    o, n = old or {}, new or {}
    out = []
    for k in sorted({*o, *n}, key=str):
        if _same(o.get(k), n.get(k)):
            continue
        if k not in keys:
            out.append(Change(f"{block}.{k}", HUMAN, "a key the module schema does not define"))
        elif k == "capabilities":
            out += _capabilities(block, o.get(k), n.get(k), priv)
        elif block == "provides" and k == "slots":
            out += _slots(o.get(k), n.get(k), priv)
        else:
            out.append(Change(f"{block}.{k}", OWNER, f"{block} {k}"))
    return out


def _needs_change(key: str, old: Any, new: Any) -> Change:
    """Owner when the new grants are a subset of the old (removed or narrowed by dropping
    entries), human-approve for anything else, an unreadable list included."""
    field = f"contributes.agents.{key}.needs"
    if new in (None, []):
        return Change(field, OWNER, "data grants removed")
    if isinstance(old, list) and isinstance(new, list):
        kept = [json.dumps(e, sort_keys=True, default=str) for e in old]
        if all(json.dumps(e, sort_keys=True, default=str) in kept for e in new):
            return Change(field, OWNER, "data grants narrowed (entries removed)")
    return Change(field, HUMAN, "an agent's data grants")


def _agents(old: Any, new: Any) -> list[Change]:
    o, n = _by(old, lambda a: a.get("key")), _by(new, lambda a: a.get("key"))
    if o is None or n is None:
        return [Change("contributes.agents", HUMAN, "not a list of keyed agents (fail closed)")]
    out = []
    for k in sorted({*o, *n}, key=str):
        a, b = o.get(k) or {}, n.get(k) or {}
        if _same(a, b):
            continue
        if not _same(a.get("needs"), b.get("needs")):
            out.append(_needs_change(k, a.get("needs"), b.get("needs")))
        rest_a = {x: v for x, v in a.items() if x != "needs"}
        rest_b = {x: v for x, v in b.items() if x != "needs"}
        if not _same(rest_a, rest_b):
            out.append(Change(f"contributes.agents.{k}", OWNER, "an agent's definition"))
    return out


def classify(
    old: dict | None, new: dict | None, keys: dict[str, set[str]], priv: set[str] | None
) -> list[Change]:
    """Every changed field between two versions of a manifest, each with its tier; ``old`` None
    is a new manifest and ``new`` None a removed one (both human-approve)."""
    if old is None and new is None:
        return []
    if old is None:
        return [Change("module", HUMAN, "a new module")]
    if new is None:
        return [Change("module", HUMAN, "a removed module")]
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [Change("module", HUMAN, "not a mapping (fail closed)")]
    out: list[Change] = []
    for k in sorted({*old, *new}, key=str):
        a, b = old.get(k), new.get(k)
        if _same(a, b):
            continue
        if k not in keys.get("", set()):
            out.append(Change(str(k), HUMAN, "a key the module schema does not define"))
        elif k in HUMAN_FIELDS:
            out.append(Change(k, HUMAN, f"{k} is human-approve"))
        elif k in ("provides", "requires", "prefers"):
            out += _block(k, a, b, keys.get(k, set()), priv)
        elif k == "contributes":
            if not isinstance(a or {}, dict) or not isinstance(b or {}, dict):
                out.append(Change(k, HUMAN, "not a mapping (fail closed)"))
                continue
            ca, cb = a or {}, b or {}
            out += _agents(ca.get("agents"), cb.get("agents"))
            if not _same(
                {x: v for x, v in ca.items() if x != "agents"},
                {x: v for x, v in cb.items() if x != "agents"},
            ):
                out.append(Change(k, OWNER, "a contribution other than an agent"))
        else:
            out.append(Change(str(k), OWNER, k))
    return out


def tier_of(changes: list[Change]) -> str | None:
    """The manifest's tier: human-approve when any change is, owner when only owner changes, None
    when nothing changed."""
    if not changes:
        return None
    return HUMAN if any(c.tier == HUMAN for c in changes) else OWNER


def load_manifest(text: str | bytes | None) -> dict | str | None:
    """The parsed manifest, None for no file, or an error string (fail closed)."""
    if text is None:
        return None
    try:
        doc = yaml.load(text, Loader=UniqueKeyLoader)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        return f"cannot be read ({exc.__class__.__name__})"
    return doc if isinstance(doc, dict) else "not a mapping"


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)


def changed_manifests(root: Path, base: str) -> list[tuple[str, Any, Any]]:
    """``(path, old, new)`` for every in-tree manifest the working tree changes against ``base``;
    old and new are parsed manifests, None (absent) or an error string."""
    if _git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}").returncode:
        raise ValueError(f"--base {base}: not a commit here")
    r = _git(root, "diff", "--no-renames", "--name-only", "-z", base, "--", *MANIFEST_GLOBS)
    if r.returncode:
        raise ValueError(f"git diff against {base} failed")
    untracked = _git(
        root, "ls-files", "-z", "--others", "--exclude-standard", "--", *MANIFEST_GLOBS
    )
    paths = {p for p in (r.stdout + untracked.stdout).decode("utf-8", "replace").split("\0") if p}
    out = []
    for p in sorted(paths):
        shown = _git(root, "show", f"{base}:{p}")
        old = load_manifest(shown.stdout if shown.returncode == 0 else None)
        f = root / p
        new = load_manifest(f.read_bytes() if f.is_file() and not f.is_symlink() else None)
        if f.is_symlink():
            new = "a symbolic link (fail closed)"
        out.append((p, old, new))
    return out


def load_codeowners(root: Path) -> tuple[str | None, list[tuple[str, list[str]]]]:
    """(the file GitHub reads, its rules as (pattern, owners)) or (None, [])."""
    for rel in CODEOWNERS_PATHS:
        f = root / rel
        if f.is_file():
            rules = []
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    pattern, *owners = line.split()
                    rules.append((pattern, owners))
            return rel, rules
    return None, []


def _codeowners_match(pattern: str, path: str) -> bool:
    """GitHub's CODEOWNERS pattern semantics, for the forms this repository uses: ``*``, a
    leading ``/`` anchors at the root, a trailing ``/`` is a directory and everything under it,
    and a pattern without a ``/`` matches a name at any depth."""
    if pattern == "*":
        return True
    anchored = pattern.startswith("/")
    pat = pattern.lstrip("/")
    if pat.endswith("/"):
        pat += "**"
    if "/" not in pat.rstrip("*") and not anchored:
        return any(
            fnmatch.fnmatchcase(part, pat) for part in path.split("/")
        ) or fnmatch.fnmatchcase(path, pat)
    if pat.endswith("/**"):
        return path.startswith(pat[:-2]) or fnmatch.fnmatchcase(path, pat[:-3] + "/*")
    return fnmatch.fnmatchcase(path, pat)


def codeowners_for(rules: list[tuple[str, list[str]]], path: str) -> list[str]:
    """The owners of ``path``: the last matching rule's (later lines take precedence)."""
    owners: list[str] = []
    for pattern, who in rules:
        if _codeowners_match(pattern, path):
            owners = who
    return owners
