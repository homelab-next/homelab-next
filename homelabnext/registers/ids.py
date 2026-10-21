# SPDX-License-Identifier: Apache-2.0
"""Loss and duplicate detection for registers: record directories keyed by uid, and the
invariants register keyed by its checklist ids.

Records are identified by a UUIDv7 created with the record (ADR-0019), so nothing is
allocated, numbered or renumbered: two authors who add a record each never collide.  What can
still go wrong is the corruption a duplicate check cannot see -- a record that silently
vanished in a merge -- and two files claiming one uid.  This module detects both:

    check_lost    fail if a key a parent commit had is absent now (a lost record)
    duplicates    a key that occurs twice in a single-file register
    dir_problems  a record file that is not named ``<uid>.md``, has no uid, or shares one
    missing_uids  record files that carry no canonical uid (a legacy ``id:`` or a placeholder)

Nothing here rewrites a file, and the module stays standard library only, for hooks.

A register is a directory of record files (``lessons/<uid>.md``, the strategy's
``objectives/<uid>.md`` ...; see :mod:`homelabnext.registers.records`) or a single YAML file
(``invariants.yml``, whose criteria ids are the checklist's row ids; a joined ``lessons.yml``,
whose entries are keyed by ``uid``).  In a directory each file's front-matter ``uid:`` is its key
and the file is named for it.  The invariants file may tombstone an id under a top-level
``retired:`` block (one ``ID:`` key per line, read as text by :func:`retired_in`)::

    retired:
      F-02:
        replaced_by: L-07
        reason: meant checklist L-07 (runbook verifies), not F-02 (network segments)

``check_lost`` counts a tombstoned id as present; ``duplicates`` refuses an id that is both
live and retired.  A record directory has no tombstones: a uid is never reused, so a record is
retired through its lifecycle (a status), never deleted.

The migration to uids (``hnx records assign-uids``) renames ``LL-001.md`` to ``<uid>.md`` and
records ``LL-001 -> <uid>`` in the tree's ``aliases.yml``.  ``check_lost`` reads a parent commit
that still has the numbered files through that map, so the migration commit itself is checked:
a code whose uid is present now is accounted for, a code with no uid now is lost.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
from dataclasses import dataclass

from homelabnext.identity.uid import UID_PATTERN

__all__ = [
    "SPECS",
    "IdError",
    "RegisterSpec",
    "check_lost",
    "dir_problems",
    "discover",
    "duplicates",
    "entry_ids",
    "ids_in",
    "is_record_dir",
    "missing_uids",
    "record_id",
    "record_name_problem",
    "retired_in",
    "spec_for",
    "split_entries",
]


class IdError(Exception):
    pass


@dataclass(frozen=True)
class RegisterSpec:
    """How one register kind keys its entries.

    key        the entry key field: ``uid`` (records) or ``id`` (the invariants' checklist ids)
    id_re      what a key looks like
    protected  a vanished key is corruption (every register here; a work queue would not be)
    """

    kind: str
    key: str
    id_re: str
    protected: bool = True


_RECORDS = ("lessons", "runbooks", "objectives", "measures", "requirements", "rfis")
SPECS: dict[str, RegisterSpec] = {
    **{k: RegisterSpec(k, "uid", UID_PATTERN) for k in _RECORDS},
    # criteria ids are docs/checklist.md row ids: chosen to match a row, never allocated
    "invariants": RegisterSpec("invariants", "id", r"[A-Z]-\d{2,}"),
}
#: a numbered code the records carried before uids (read only to check the migration commit)
_LEGACY = re.compile(r"(?:LL|RB|SO|OO|TO|TT|MOP|MOE|CCIR|FFIR|PIR|RFI)-(?:\d{3,}|NEW)")
_ALIAS_LINE = re.compile(rf"(?m)^[ \t]+({_LEGACY.pattern})[ \t]*:[ \t]*({UID_PATTERN})\b")
ALIASES_FILE = "aliases.yml"


def spec_for(path: str | os.PathLike) -> RegisterSpec | None:
    """Register kind is taken from the file stem or directory name: lessons/, invariants.yml"""
    return SPECS.get(pathlib.Path(path).stem.split(".")[0])


REGISTER_SUFFIXES = (".yml", ".yaml")
RECORD_SUFFIX = ".md"
_FRONT = re.compile(r"\A---\r?\n(.*?)(?:\r?\n)?^---[ \t]*$", re.S | re.M)


def _fm_key(key: str) -> re.Pattern:
    return re.compile(rf"(?m)^{key}:[ \t]*(['\"]?)([^\s'\"#]+)\1[ \t]*(?:#.*)?$")


_FM_UID, _FM_ID = _fm_key("uid"), _fm_key("id")


def is_record_dir(path: str | os.PathLike) -> bool:
    """A directory register, existing or not (a path without a YAML suffix)."""
    p = pathlib.Path(path)
    return p.is_dir() or (not p.exists() and p.suffix not in REGISTER_SUFFIXES)


def record_id(text: str, spec: RegisterSpec) -> str | None:
    """A record file's canonical uid, read from its front-matter as text (None without one)."""
    m = _FRONT.match(text)
    um = _FM_UID.search(m.group(1)) if m else None
    return um.group(2) if um and re.fullmatch(spec.id_re, um.group(2)) else None


def _legacy_id(text: str) -> str | None:
    """The numbered ``id:`` of a record file written before uids (a parent commit's)."""
    m = _FRONT.match(text)
    im = _FM_ID.search(m.group(1)) if m else None
    return im.group(2) if im and _LEGACY.fullmatch(im.group(2)) else None


def record_name_problem(name: str, ident: str | None, spec: RegisterSpec) -> str | None:
    """Why a record file's name does not fit its uid, or None.  The uid is the key; the name
    must agree so that ``[[<uid>]]`` resolves to the file and two files cannot share a uid."""
    if not name.endswith(RECORD_SUFFIX):
        return f"{name}: a record file must end in {RECORD_SUFFIX}"
    stem = name[: -len(RECORD_SUFFIX)]
    if ident is None:
        return (
            f"{name}: front-matter has no canonical `uid:` (a UUIDv7); a record written before "
            "uids is migrated with `hnx records assign-uids`"
        )
    if stem != ident:
        return f"{name}: file name and front-matter uid {ident} disagree (name it {ident}.md)"
    return None


def _dir_keys(texts: dict[str, str], spec: RegisterSpec) -> list[tuple[str, str]]:
    """[(key, file name)] of a directory register's record texts: the uid, or for a file
    written before uids its legacy code (only a parent commit has those)."""
    out = []
    for name in sorted(texts):
        ident = record_id(texts[name], spec) or _legacy_id(texts[name])
        if ident is not None:
            out.append((ident, name))
    return out


def dir_problems(texts: dict[str, str], spec: RegisterSpec) -> list[str]:
    """Name/uid disagreements, files without a uid and uids held by more than one file."""
    problems, seen = [], {}
    for name in sorted(texts):
        ident = record_id(texts[name], spec)
        bad = record_name_problem(name, ident, spec)
        if bad:
            problems.append(bad)
        if ident is None:
            continue
        if ident in seen:
            problems.append(f"{name}: uid {ident} is also the uid of {seen[ident]}")
        else:
            seen[ident] = name
    return problems


def missing_uids(texts: dict[str, str], spec: RegisterSpec) -> list[str]:
    """Record files with no canonical uid: a legacy numbered ``id:`` or an ``XX-NEW``
    placeholder (``hnx records assign-uids`` gives each its uid)."""
    out = []
    for name in sorted(texts):
        if record_id(texts[name], spec) is None:
            legacy = _legacy_id(texts[name])
            out.append(f"{name}: no uid" + (f" (still numbered {legacy})" if legacy else ""))
    return out


def _disk_dir_texts(path: pathlib.Path) -> dict[str, str] | None:
    if not path.is_dir():
        return None
    return {
        p.name: p.read_text()
        for p in path.iterdir()
        if p.is_file() and not p.name.startswith(".") and p.suffix == RECORD_SUFFIX
    }


def _rev_dir_texts(root, rev: str, relpath: str) -> dict[str, str] | None:
    """Every ``*.md`` blob directly under ``relpath`` at ``rev``, in one ``git cat-file`` call."""
    out = _git(root, "ls-tree", "-z", rev, "--", relpath.rstrip("/") + "/")
    if out.returncode:
        return None
    entries = []
    for rec in out.stdout.split("\0"):
        if not rec:
            continue
        meta, _, path = rec.partition("\t")
        _mode, kind, sha = meta.split()
        name = path.rsplit("/", 1)[-1]
        if kind == "blob" and name.endswith(RECORD_SUFFIX) and not name.startswith("."):
            entries.append((name, sha))
    if not entries:
        return None
    cat = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=root,
        input="".join(f"{sha}\n" for _, sha in entries).encode(),
        capture_output=True,
    )
    if cat.returncode:
        raise IdError(f"git cat-file failed reading {relpath} at {rev}")
    data, pos, texts = cat.stdout, 0, {}
    for name, _sha in entries:
        nl = data.index(b"\n", pos)
        size = int(data[pos:nl].split()[2])
        texts[name] = data[nl + 1 : nl + 1 + size].decode()
        pos = nl + 1 + size + 1
    return texts


def _sibling_file(relpath: str) -> list[str]:
    return [relpath.rstrip("/") + s for s in REGISTER_SUFFIXES]


def _known_at(root, relpath: str, spec: RegisterSpec, rev: str | None = None) -> set[str] | None:
    """Every key a register accounts for (live and retired) in the working tree or at ``rev``;
    None when the register does not exist there.  A directory register that is missing falls
    back to the single file of the same name (either side of a split or a join)."""
    root = pathlib.Path(root)
    if is_record_dir(root / relpath):
        texts = (
            _disk_dir_texts(root / relpath) if rev is None else _rev_dir_texts(root, rev, relpath)
        )
        if texts is not None:
            return {i for i, _ in _dir_keys(texts, spec)}
        candidates = _sibling_file(relpath)
    else:
        candidates = [relpath]
    for rel in candidates:
        if rev is None:
            p = root / rel
            text = p.read_text() if p.is_file() else None
        else:
            text = git_show(root, rev, rel)
        if text is not None:
            return _known(text, spec)
    return None


def _aliases(root, relpath: str) -> dict[str, str]:
    """``code -> uid`` from the ``aliases.yml`` in or above a register (the working tree's)."""
    out: dict[str, str] = {}
    d = (pathlib.Path(root) / relpath).parent
    for p in (d / ALIASES_FILE, d.parent / ALIASES_FILE):
        if p.is_file():
            out.update(dict(_ALIAS_LINE.findall(p.read_text(encoding="utf-8"))))
    return out


def entry_ids(root, relpath: str, spec: RegisterSpec) -> list[str]:
    """Live entry keys of a working-tree register (file order, or file-name order)."""
    path = pathlib.Path(root) / relpath
    if is_record_dir(path):
        return [i for i, _ in _dir_keys(_disk_dir_texts(path) or {}, spec)]
    return ids_in(path.read_text(), spec) if path.is_file() else []


def discover(root, revs: tuple[str, ...] = ("HEAD",)) -> list[str]:
    """Register paths tracked in the index or present at any of ``revs``: ``*/invariants.yml``
    style files and the directories that hold ``*/lessons/*.md``-style record files."""
    names: list[str] = []
    out = _git(root, "ls-files", "-z")
    if out.returncode:
        raise IdError("not inside a git work tree")
    names += out.stdout.split("\0")
    for rev in revs:
        if rev and _rev_exists(root, rev):
            names += _git(root, "ls-tree", "-r", "-z", "--name-only", rev).stdout.split("\0")
    found: list[str] = []
    for n in names:
        p = pathlib.PurePosixPath(n)
        if p.suffix in REGISTER_SUFFIXES and spec_for(p):
            found.append(n)
        elif p.suffix == RECORD_SUFFIX and str(p.parent) != "." and spec_for(p.parent.name):
            found.append(str(p.parent))
    return sorted(set(found))


def _anchor(spec: RegisterSpec) -> re.Pattern:
    return re.compile(rf"(?m)^- {spec.key}: ['\"]?({spec.id_re})['\"]?\s*$")


def split_entries(text: str, spec: RegisterSpec):
    """(header, [(key, block_text)]) - a pure, byte-reversible text split."""
    marks = [(m.start(), m.group(1)) for m in _anchor(spec).finditer(text)]
    if not marks:
        return text, []
    blocks = []
    for i, (pos, ident) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        blocks.append((ident, text[pos:end]))
    return text[: marks[0][0]], blocks


def ids_in(text: str, spec: RegisterSpec) -> list[str]:
    return [i for i, _ in split_entries(text, spec)[1]]


_RETIRED_HEAD = re.compile(r"^retired:[ \t]*(?:#.*)?$")
_KEY = re.compile(r"^([ \t]+)([^\s#:][^:]*?)[ \t]*:(?:[ \t]|$)")


def retired_in(text: str, spec: RegisterSpec) -> list[str]:
    """Ids tombstoned under the top-level ``retired:`` block mapping (read as text).

    Keys are the lines at the block's first indentation level; only keys that look like this
    register's ids count (the schema validator reports any other key).
    """
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if _RETIRED_HEAD.match(ln)), None)
    if start is None:
        return []
    rx = re.compile(spec.id_re)
    found, indent = [], None
    for ln in lines[start + 1 :]:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if not ln[0].isspace():
            break  # the next top-level key ends the block
        m = _KEY.match(ln)
        if indent is None and m:
            indent = m.group(1)
        if m and m.group(1) == indent:
            key = m.group(2).strip("'\"")
            if rx.fullmatch(key):
                found.append(key)
    return sorted(set(found))


def _known(text: str, spec: RegisterSpec) -> set[str]:
    """Every key the file accounts for: live entries plus tombstones (and, for a joined
    records file written before uids, its numbered ids)."""
    keys = set(ids_in(text, spec)) | set(retired_in(text, spec))
    if spec.key == "uid":
        keys |= {m.group(1) for m in re.finditer(rf"(?m)^- id: ({_LEGACY.pattern})\s*$", text)}
    return keys


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)


def git_show(root, rev: str, relpath: str):
    out = _git(root, "show", f"{rev}:{relpath}")
    return out.stdout if out.returncode == 0 else None


def repo_root(start=None) -> pathlib.Path:
    out = _git(start or os.getcwd(), "rev-parse", "--show-toplevel")
    if out.returncode:
        raise IdError("not inside a git work tree")
    return pathlib.Path(out.stdout.strip())


def _rev_exists(root, rev: str) -> bool:
    return _git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}").returncode == 0


def check_lost(
    root, relpath: str, allow: set[str] | None = None, base: str | None = None
) -> list[str]:
    """Keys present in a parent commit but absent from the working register.

    Parents: HEAD, plus MERGE_HEAD / CHERRY_PICK_HEAD / REBASE_HEAD during conflict resolution
    (when the record that vanished came from the OTHER side). With ``base`` (CI: the pull
    request's base commit) that revision is the only parent. ``allow`` or the environment
    variable ``REGISTER_IDS_ALLOW_DROP=KEY,KEY`` waives a deliberate removal.  An invariant id
    moved into the ``retired:`` mapping is still accounted for; removing that tombstone is not.
    A parent's legacy code (``LL-001``, before the uid migration) is accounted for when the
    tree's ``aliases.yml`` maps it to a uid that is present now.
    """
    root = pathlib.Path(root)
    spec = spec_for(relpath)
    if spec is None or not spec.protected:
        return []
    now = _known_at(root, relpath, spec)
    if now is None:
        if not is_record_dir(root / relpath):
            return []  # a deleted single-file register (its records directory is checked)
        now = set()  # every record file of a directory register deleted: each one is lost
    parents: set[str] = set()
    revs = (base,) if base else ("HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REBASE_HEAD")
    if base and not _rev_exists(root, base):
        raise IdError(f"base revision {base!r} does not exist (fetch it first)")
    for rev in revs:
        if _rev_exists(root, rev):
            parents |= _known_at(root, relpath, spec, rev) or set()
    if spec.key == "uid":
        aliases = _aliases(root, relpath)
        now |= {code for code, uid in aliases.items() if uid in now}
        parents = {k for k in parents if not k.endswith("-NEW")}  # never a record's identity
    waived = set(allow or ()) | {
        s.strip() for s in os.environ.get("REGISTER_IDS_ALLOW_DROP", "").split(",") if s.strip()
    }
    return sorted(parents - now - waived)


def duplicates(text: str, spec: RegisterSpec) -> list[str]:
    """Keys that occur more than once in a single-file register, counting a tombstone as an
    occurrence (a live entry reusing a retired invariant id is a duplicate)."""
    seen: set[str] = set(retired_in(text, spec))
    dupes: set[str] = set()
    for ident in ids_in(text, spec):
        if ident in seen:
            dupes.add(ident)
        seen.add(ident)
    return sorted(dupes)
