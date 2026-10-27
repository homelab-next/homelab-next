# SPDX-License-Identifier: Apache-2.0
"""The per-field review tier of an in-tree module (ADR-0027 follow-up 4; docs/modules.md, "Trust
tiers").

A change needs a **human approve** when it reaches what the Trust-tiers table gives an approver
other than the module's owner: what a module may do with trust (``credentials``,
``control_plane``, ``egress``, ``data``, ``lifecycle``, an agent and its data grants, roles and
playbooks, entry points, fleet units, service rows, MCP records, shared config, preflight hooks,
workflow packs, a privileged slot it provides, requires, prefers or falls back to) or what it is
(``id``, ``kind``, ``origin``, its interfaces); a change to a file those contributions point at,
and to any file in the module no contribution names (code, an adapter), counts the same.  Any
other change needs only the **owner**.  Everything fails closed: a new, removed, renamed,
unreadable or linked manifest or file, a key the module schema (as of the base commit) does not
define, a list it cannot key, keys it cannot compare, and, without a readable slot registry at
both the base and the head, every slot change are human-approve.  A change to what decides the
tier (the slot registry, the module schema, CODEOWNERS, this module) is human-approve too, and so
is a change to what vouches for a model a swap rebinds to (:data:`EVIDENCE`, :data:`EVIDENCE_DIRS`:
the model store, the evaluation reports and the golden suites, which the swap check reads from the
base, so vetting a model is its own reviewed change).

The approval itself is the pull request's code-owner review: :func:`review` reads CODEOWNERS **as
of the base commit** (the rules GitHub applies to the pull request) and reports a problem for every
human-approve change without a valid owner.  It does not read approvals; nothing here
authenticates a reviewer.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homelabnext.modules import loader as ld
from homelabnext.modules import swap_evidence as _se

__all__ = [
    "EVIDENCE",
    "EVIDENCE_DIRS",
    "GOVERNANCE",
    "HUMAN",
    "OWNER",
    "Change",
    "Result",
    "classify",
    "codeowners_for",
    "parse_codeowners",
    "privileged_slots",
    "review",
    "schema_keys",
    "tier_of",
    "valid_owner",
]

HUMAN = "human-approve"
OWNER = "owner"
#: top-level fields whose change always needs a human approve
HUMAN_FIELDS = (
    "credentials",
    "control_plane",
    "egress",
    "data",
    "lifecycle",
    "interfaces",
    "id",
    "kind",
    "origin",
)
#: contributions the Trust-tiers table gives an approver other than the owner: roles and
#: playbooks (root on hosts), entry points (code in core processes), fleet units, service rows,
#: agents, MCP records, shared config, and the hooks and workflow packs that run on hosts
HUMAN_CONTRIBUTIONS = frozenset(
    {
        "roles",
        "entry_points",
        "scheduler_jobs",
        "services",
        "agents",
        "mcp_servers",
        "shared_config",
        "preflight",
        "workflow_packs",
    }
)
#: contributions the owner approves: rules, docs, criteria, tables, paging pairs, status sources
OWNER_CONTRIBUTIONS = frozenset(
    {"detections", "docs", "invariants", "lake_tables", "notify_pairs", "status_sources"}
)
#: the module roots the tier covers, relative to the repository root
MODULE_ROOTS = ("modules", "examples/modules")
SLOTS = "examples/modules/slots.yml"
SCHEMA = "schemas/platform/module.schema.json"
#: where GitHub reads CODEOWNERS from, first found wins
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
#: what decides the tier: a change to any of these is human-approve
GOVERNANCE = (
    SLOTS,
    SCHEMA,
    *CODEOWNERS_PATHS,
    "homelabnext/modules/review_tier.py",
    "homelabnext/gitbase.py",  # the base rule --ci-base takes
    "tools/schema_check.py",  # which re-exports it for the repository's tools
    ".github/workflows/ci.yml",  # the step that runs the check
)
#: what vouches for a model in a swap (homelabnext.modules.swap_evidence reads each from the base,
#: so a change here is the vetting step that a later rebind relies on): the model store, the
#: evaluation reports and the golden suites they are checked with
EVIDENCE = (_se.STORE, *_se.REPORTS, *_se.SUITES)
#: directories whose every file vouches the same way: the live reports of proposed tables
EVIDENCE_DIRS = (_se.EVALS,)
#: git's empty tree, the base of a root commit
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@dataclass(frozen=True)
class Change:
    field: str  # a dotted path (credentials, provides.slots.secrets) or file:<module path>
    tier: str  # HUMAN or OWNER
    why: str


@dataclass
class Result:
    path: str  # the manifest (or governance file) the changes are reported under
    changes: list[Change]
    owners: list[str] = field(default_factory=list)

    @property
    def tier(self) -> str | None:
        return tier_of(self.changes)


def tier_of(changes: list[Change]) -> str | None:
    """Human-approve when any change is, owner when only owner changes, None for no change."""
    if not changes:
        return None
    return HUMAN if any(c.tier == HUMAN for c in changes) else OWNER


# ------------------------------------------------------------------------------- the inputs


def schema_keys(schema: Any) -> dict[str, set[str]]:
    """The keys the module schema defines: ``""`` for the top level, per block (``provides``,
    ``requires``, ``prefers``) and ``contributes``; all empty for an unreadable schema, so every
    change is an undefined key (fail closed)."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    defs = schema.get("$defs") or {}

    def keys_of(node: Any) -> set[str]:
        if not isinstance(node, dict):
            return set()
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            node = defs.get(ref.rsplit("/", 1)[-1]) or {}
        return set(node.get("properties") or {}) if isinstance(node, dict) else set()

    out = {"": set(props) if isinstance(props, dict) else set()}
    for block in ("provides", "requires", "prefers", "contributes"):
        out[block] = keys_of(props.get(block)) if isinstance(props, dict) else set()
    return out


def privileged_slots(slot_registry: Any) -> set[str] | None:
    """``cap:<slot>`` for every slot the registry marks ``privileged``, or None when it cannot be
    read or names no slot (every slot change is then human-approve)."""
    slots = slot_registry.get("slots") if isinstance(slot_registry, dict) else None
    if not isinstance(slots, dict) or not slots:
        return None
    return {f"cap:{s}" for s, d in slots.items() if isinstance(d, dict) and d.get("privileged")}


def _parse(data: bytes | None, *, json_doc: bool = False) -> Any:
    """A YAML (or JSON) document read like the loader reads one (size capped, duplicate keys,
    aliases and deep nesting refused), None for no file; an unreadable one raises Unreadable."""
    if data is None:
        return None
    if len(data) > ld.MAX_BYTES:
        raise ld.Unreadable(f"over {ld.MAX_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ld.Unreadable("not UTF-8") from None
    if json_doc:
        try:
            return json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ld.Unreadable(f"not JSON ({exc.__class__.__name__})") from None
    return ld.parse_yaml(text)


def _same(a: Any, b: Any) -> bool:
    """Deep equality by canonical JSON; keys that cannot be ordered raise TypeError, which the
    caller turns into a human-approve change."""
    return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)


# ------------------------------------------------------------------------------- a manifest


def _diff(old: Any, new: Any) -> list[tuple[Any, Any, Any]] | None:
    """``(key, old value, new value)`` for every key two mappings disagree on, or None when
    either is not a mapping (an absent one is empty)."""
    if not isinstance(old or {}, dict) or not isinstance(new or {}, dict):
        return None
    o, n = old or {}, new or {}
    return [
        (k, o.get(k), n.get(k)) for k in sorted({*o, *n}, key=str) if not _same(o.get(k), n.get(k))
    ]


def _by(items: Any, key) -> dict | None:
    """A list of mappings indexed by ``key(item)``, or None when it is not one or two items
    share a key (fail closed)."""
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


def _cap_key(e: dict):
    cap = e.get("cap")
    return (cap, e.get("instance")) if isinstance(cap, str) else None


def _cap_refs(e: Any) -> set[str]:
    """Every capability an entry names: its own and its fallback's."""
    if not isinstance(e, dict):
        return set()
    out = {e["cap"]} if isinstance(e.get("cap"), str) else set()
    fb = e.get("fallback")
    if isinstance(fb, dict) and isinstance(fb.get("to"), str):
        out.add(fb["to"])
    return out


def _capabilities(block: str, old: Any, new: Any, priv: set[str] | None) -> list[Change]:
    name = f"{block}.capabilities"
    o, n = _by(old, _cap_key), _by(new, _cap_key)
    if o is None or n is None:
        return [Change(name, HUMAN, "not a list of distinct capability entries (fail closed)")]
    out = []
    for k in sorted({*o, *n}, key=str):
        if _same(o.get(k), n.get(k)):
            continue
        cap, inst = k
        where = f"{name}.{cap}" + (f"[{inst}]" if inst else "")
        refs = _cap_refs(o.get(k)) | _cap_refs(n.get(k))
        if priv is None:
            out.append(Change(where, HUMAN, "no slot registry to tell a privileged slot"))
        elif refs & priv:
            hit = ", ".join(sorted(refs & priv))
            out.append(Change(where, HUMAN, f"names a privileged slot ({hit})"))
        else:
            out.append(Change(where, OWNER, "a capability entry"))
    return out


def _slots(old: Any, new: Any, priv: set[str] | None) -> list[Change]:
    diff = _diff(old, new)
    if diff is None:
        return [Change("provides.slots", HUMAN, "not a mapping of slots (fail closed)")]
    out = []
    for s, _, _ in diff:
        where = f"provides.slots.{s}"
        if priv is None:
            out.append(Change(where, HUMAN, "no slot registry to tell a privileged slot"))
        elif f"cap:{s}" in priv:
            out.append(Change(where, HUMAN, f"cap:{s} is a privileged slot"))
        else:
            out.append(Change(where, OWNER, "a provided slot (its adapter is code: see its files)"))
    return out


def _block(block: str, old: Any, new: Any, keys: set[str], priv: set[str] | None) -> list[Change]:
    diff = _diff(old, new)
    if diff is None:
        return [Change(block, HUMAN, "not a mapping (fail closed)")]
    out = []
    for k, a, b in diff:
        if k not in keys:
            out.append(Change(f"{block}.{k}", HUMAN, "a key the module schema does not define"))
        elif k == "capabilities":
            out += _capabilities(block, a, b, priv)
        elif block == "provides" and k == "slots":
            out += _slots(a, b, priv)
        elif k == "interfaces":
            out.append(Change(f"{block}.{k}", HUMAN, "interfaces (a gate's ownership)"))
        else:
            out.append(Change(f"{block}.{k}", OWNER, f"{block} {k}"))
    return out


def _needs_change(key: str, old: Any, new: Any) -> Change:
    """Owner when the new grants are a subset of the old (removed, or narrowed by dropping
    entries), human-approve for anything else, an unreadable list included."""
    where = f"contributes.agents.{key}.needs"
    if new in (None, []):
        return Change(where, OWNER, "data grants removed")
    if isinstance(old, list) and isinstance(new, list):
        kept = [json.dumps(e, sort_keys=True, default=str) for e in old]
        if all(json.dumps(e, sort_keys=True, default=str) in kept for e in new):
            return Change(where, OWNER, "data grants narrowed (entries removed)")
    return Change(where, HUMAN, "an agent's data grants")


def _agents(old: Any, new: Any) -> list[Change]:
    o, n = _by(old, lambda a: a.get("key")), _by(new, lambda a: a.get("key"))
    if o is None or n is None:
        return [Change("contributes.agents", HUMAN, "not a list of distinct keyed agents")]
    out = []
    for k in sorted({*o, *n}, key=str):
        a, b = o.get(k), n.get(k)
        if _same(a, b):
            continue
        if a is None or b is None:
            out.append(Change(f"contributes.agents.{k}", HUMAN, "an agent added or removed"))
            continue
        if not _same(a.get("needs"), b.get("needs")):
            out.append(_needs_change(k, a.get("needs"), b.get("needs")))
        rest_a = {x: v for x, v in a.items() if x != "needs"}
        rest_b = {x: v for x, v in b.items() if x != "needs"}
        if not _same(rest_a, rest_b):
            out.append(
                Change(f"contributes.agents.{k}", HUMAN, "an agent's definition (its policy owner)")
            )
    return out


def _contributes(old: Any, new: Any, keys: set[str]) -> list[Change]:
    diff = _diff(old, new)
    if diff is None:
        return [Change("contributes", HUMAN, "not a mapping (fail closed)")]
    out = []
    for k, a, b in diff:
        where = f"contributes.{k}"
        if k not in keys:
            out.append(Change(where, HUMAN, "a key the module schema does not define"))
        elif k == "agents":
            out += _agents(a, b)
        elif k in HUMAN_CONTRIBUTIONS:
            out.append(Change(where, HUMAN, "a contribution with an approver other than the owner"))
        elif k in OWNER_CONTRIBUTIONS:
            out.append(Change(where, OWNER, "a contribution its owner approves"))
        else:
            out.append(Change(where, HUMAN, "a contribution the tier does not rate (fail closed)"))
    return out


def classify(old: Any, new: Any, keys: dict[str, set[str]], priv: set[str] | None) -> list[Change]:
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
    try:
        return _classify(old, new, keys, priv)
    except TypeError as exc:  # keys of mixed types cannot be ordered to compare
        return [Change("module", HUMAN, f"cannot be compared ({exc}) (fail closed)")]


def _classify(
    old: dict, new: dict, keys: dict[str, set[str]], priv: set[str] | None
) -> list[Change]:
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
            out += _contributes(a, b, keys.get("contributes", set()))
        else:
            out.append(Change(str(k), OWNER, k))
    return out


# ------------------------------------------------------------------------------- module files


def _references(doc: Any) -> dict[str, set[str]]:
    """``{module-relative path: {contribution keys naming it}}`` from one manifest version."""
    out: dict[str, set[str]] = {}
    if not isinstance(doc, dict):
        return out
    try:
        for key, rel in ld.contributed_files(doc):
            if isinstance(rel, str):
                out.setdefault(rel.rstrip("/"), set()).add(key)
    except (AttributeError, TypeError, KeyError):
        pass  # a malformed manifest: its files fall to "named by no contribution"
    return out


def _named_by(rel: str, refs: dict[str, set[str]], *, dirs_only: bool = False) -> set[str]:
    """The contribution keys naming ``rel``: the path itself, or a directory above it."""
    keys: set[str] = set()
    for path, ks in refs.items():
        if (rel == path and not dirs_only) or rel.startswith(path + "/"):
            keys |= ks
    return keys


def _rated(keys: set[str], privileged_provider: bool) -> set[str]:
    """The human-rated keys among ``keys``: every key but the owner contributions, and a
    conformance target only for a provider of a privileged slot."""
    out = keys - OWNER_CONTRIBUTIONS
    if not privileged_provider:
        out.discard("conformance")
    return out


def _file_change(
    rel: str,
    base_refs: dict[str, set[str]],
    head_refs: dict[str, set[str]],
    *,
    at_base: bool,
    privileged_provider: bool,
) -> Change:
    """The tier of a change to a file in a module.  A file the base has takes the tier of what
    the **base** manifest names it by; a new file only by a directory the base names above it,
    else it is human-approve; the head's manifest can only add human-rated names, never make a
    file owner (a pull request cannot name its own unreviewed file as docs); a file nothing names
    (code, an adapter) is human-approve."""
    where = f"file:{rel}"
    keys = _named_by(rel, base_refs, dirs_only=not at_base)
    head_rated = _rated(_named_by(rel, head_refs), privileged_provider)
    rated = _rated(keys, privileged_provider) | head_rated
    if rated:
        return Change(where, HUMAN, f"named by {', '.join(sorted(rated))}")
    if not keys:
        why = (
            "named by no contribution at the base"
            if at_base
            else "a new file the base names no directory of"
        )
        return Change(where, HUMAN, f"{why} (code, an adapter) (fail closed)")
    return Change(where, OWNER, f"named by {', '.join(sorted(keys))} at the base")


# ------------------------------------------------------------------------------- CODEOWNERS

_OWNER = re.compile(
    r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?$"
    r"|^[^@\s/]+@[^@\s/]+\.[A-Za-z0-9-]+$"
)


def valid_owner(token: str) -> bool:
    """An owner GitHub accepts: ``@user``, ``@org/team`` or an email address."""
    return bool(_OWNER.match(token))


def _split_unescaped(line: str) -> list[str]:
    """Whitespace-separated tokens, ``\\ `` and ``\\#`` escaped, a ``#`` starting a comment."""
    tokens, cur, i = [], "", 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur += "\\" + line[i + 1]
            i += 2
            continue
        if ch == "#":
            break
        if ch.isspace():
            if cur:
                tokens.append(cur)
                cur = ""
        else:
            cur += ch
        i += 1
    if cur:
        tokens.append(cur)
    return tokens


def _pattern_regex(pattern: str) -> tuple[re.Pattern[str], bool]:
    """(the regex a path or one of its directories must match, directory-only), by GitHub's
    gitignore-style rules: ``*`` and ``?`` stay within one path segment, ``**`` spans
    directories, a ``/`` anywhere but the end anchors at the root, a trailing ``/`` matches a
    directory only, character classes are not supported (a ``[`` is literal), and ``\\``
    escapes the next character."""
    dir_only = pattern.endswith("/")
    pat = pattern.rstrip("/")
    anchored = "/" in pat
    pat = pat.lstrip("/")
    out, i = "", 0
    while i < len(pat):
        ch = pat[i]
        if ch == "\\" and i + 1 < len(pat):
            out += re.escape(pat[i + 1])
            i += 2
        elif pat.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out += "/.*"
            i += 3
        elif pat.startswith("**", i):
            out += ".*"
            i += 2
        elif ch == "*":
            out += "[^/]*"
            i += 1
        elif ch == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(ch)
            i += 1
    prefix = "" if anchored else "(?:.*/)?"
    return re.compile(f"^{prefix}{out}$"), dir_only


def parse_codeowners(text: str) -> list[tuple[str, list[str]]]:
    """The rules, in order: (pattern, valid owners). A rule with no valid owner leaves its paths
    unowned (GitHub reads an owner it cannot resolve as none); section headers are skipped."""
    rules = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^\^?\[[^\]]*\](\[\d+\])?(\s+\S+)*$", stripped) and not stripped.startswith(
            "\\"
        ):
            continue  # a section header (another forge's syntax): it owns nothing
        tokens = _split_unescaped(stripped)
        if not tokens:
            continue
        rules.append((tokens[0], [t for t in tokens[1:] if valid_owner(t)]))
    return rules


def codeowners_for(rules: list[tuple[str, list[str]]], path: str) -> list[str]:
    """The owners of ``path``: the last rule that matches it or a directory above it."""
    parts = path.split("/")
    dirs = ["/".join(parts[:i]) for i in range(1, len(parts))]
    owners: list[str] = []
    for pattern, who in rules:
        rx, dir_only = _pattern_regex(pattern)
        if pattern.rstrip("/").endswith("/*"):
            # GitHub: ``docs/*`` owns docs/'s own files, not those of its subdirectories
            candidates = [path]
        else:
            candidates = dirs if dir_only else [*dirs, path]
        if any(rx.match(c) for c in candidates):
            owners = who
    return owners


# ------------------------------------------------------------------------------- the review


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)


def _show(root: Path, base: str, rel: str) -> bytes | None:
    r = _git(root, "show", f"{base}:./{rel}")
    return r.stdout if r.returncode == 0 else None


def _version(data: bytes | str | None, *, json_doc: bool = False) -> tuple[Any, str | None]:
    """(the parsed document or None, why it cannot be read or None)."""
    if isinstance(data, str):
        return None, data
    try:
        return _parse(data, json_doc=json_doc), None
    except ld.Unreadable as exc:
        return None, str(exc)


def changed_paths(root: Path, base: str) -> list[str]:
    """Every path under the module roots or among the governance files that the working tree
    changes against ``base`` (a rename is a removal and an addition), untracked files included."""
    if _git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{tree}}").returncode:
        raise ValueError(f"--base {base}: not a commit here")
    spec = [*MODULE_ROOTS, *GOVERNANCE, *EVIDENCE, *EVIDENCE_DIRS]
    r = _git(root, "diff", "--no-renames", "--name-only", "-z", base, "--", *spec)
    if r.returncode:
        raise ValueError(f"git diff against {base} failed")
    u = _git(root, "ls-files", "-z", "--others", "--exclude-standard", "--", *spec)
    return sorted({p for p in (r.stdout + u.stdout).decode("utf-8", "replace").split("\0") if p})


def _module_dir(rel: str) -> str | None:
    """``modules/<id>`` or ``examples/modules/<id>`` for a path inside one, else None."""
    for r in sorted(MODULE_ROOTS, key=len, reverse=True):
        if rel.startswith(r + "/"):
            rest = rel[len(r) + 1 :].split("/", 1)
            return f"{r}/{rest[0]}" if len(rest) == 2 else None
    return None


def review(root: Path, base: str) -> tuple[list[Result], list[str]]:
    """(each changed manifest's or governance file's changes and owners, the problems: a
    human-approve change with no valid code owner as of ``base``, or CODEOWNERS unreadable)."""
    paths = changed_paths(root, base)
    problems: list[str] = []
    # the inputs that decide the tier, as of the base (a pull request cannot loosen them for
    # itself); the slot registry also as of the head, so neither side can drop a privileged slot
    keys = schema_keys(_version(_show(root, base, SCHEMA), json_doc=True)[0])
    base_slots, _ = _version(_show(root, base, SLOTS))
    head_slots, _ = _version(ld.read_tree_file(root, SLOTS))
    bp, hp = privileged_slots(base_slots), privileged_slots(head_slots)
    priv = None if bp is None or hp is None else bp | hp
    rules: list[tuple[str, list[str]]] = []
    owners_from = None
    for rel in CODEOWNERS_PATHS:
        data = _show(root, base, rel)
        if data is not None:
            owners_from = rel
            try:
                rules = parse_codeowners(data.decode("utf-8"))
            except UnicodeDecodeError:
                problems.append(f"{rel} at {base[:12]}: not UTF-8, so no change has a code owner")
            break
    results: dict[str, Result] = {}
    modules: dict[str, list[str]] = {}
    for rel in paths:
        if rel in GOVERNANCE:
            results[rel] = Result(rel, [Change(rel, HUMAN, "decides the review tier itself")])
            continue
        if rel in EVIDENCE or any(rel.startswith(d + "/") for d in EVIDENCE_DIRS):
            why = "vouches for a model a later swap rebinds to (read from the base)"
            results[rel] = Result(rel, [Change(rel, HUMAN, why)])
            continue
        d = _module_dir(rel)
        if d is None:
            results[rel] = Result(
                rel, [Change(f"file:{rel}", HUMAN, "not in a module directory (fail closed)")]
            )
            continue
        modules.setdefault(d, []).append(rel)
    for d, rels in modules.items():
        mpath = f"{d}/module.yml"
        old, old_err = _version(_show(root, base, mpath))
        new, new_err = _version(ld.read_tree_file(root, mpath))
        changes: list[Change] = []
        if mpath in rels:
            if old_err or new_err:
                changes.append(Change("module", HUMAN, f"{old_err or new_err} (fail closed)"))
            else:
                changes += classify(old, new, keys, priv)
        base_refs, head_refs = _references(old), _references(new)
        provided = set()
        for doc in (old, new):
            slots = (doc.get("provides") or {}).get("slots") if isinstance(doc, dict) else None
            if isinstance(slots, dict):
                provided |= {f"cap:{s}" for s in slots}
        privileged_provider = priv is None or bool(provided & priv)
        for rel in rels:
            if rel == mpath:
                continue
            inner = rel[len(d) + 1 :]
            if ld.path_has_symlink(root, rel):
                changes.append(Change(f"file:{inner}", HUMAN, "a symbolic link on its path"))
            else:
                changes.append(
                    _file_change(
                        inner,
                        base_refs,
                        head_refs,
                        at_base=_show(root, base, rel) is not None,
                        privileged_provider=privileged_provider,
                    )
                )
        results[mpath] = Result(mpath, changes)
    out = []
    for r in sorted(results.values(), key=lambda r: r.path):
        if r.tier is None:
            continue
        r.owners = codeowners_for(rules, r.path)
        if r.tier == HUMAN and not r.owners:
            problems.append(
                f"{r.path}: a human-approve change, and no valid CODEOWNERS owner as of "
                f"{base[:12]} ({owners_from or 'no CODEOWNERS file'}) whose review approves it"
            )
        out.append(r)
    return out, problems
