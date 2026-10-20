# SPDX-License-Identifier: Apache-2.0
"""Id allocation and loss detection for registers: one YAML file, or one record file per entry.

Two authors who both read "the next free id" out of a file and append an entry collide. This
module removes the read-then-write race and detects the one corruption a duplicate-id check
cannot see (an entry that silently vanished in a merge).

    alloc       claim ids under a per-repository flock; two racers get N and N+1
    resolve     rewrite ``XX-NEW`` placeholders (``LL-NEW``, ``RB-NEW`` ...) into allocated ids
    check_lost  fail if an id a parent commit had is absent from the file being committed
    placeholders  the ``XX-NEW`` entry ids still in a file (CI fails a push to main with any)

Nothing here rewrites YAML: entries are split as text so comments survive byte for byte, and an
existing id is never renumbered (and the module stays standard library only, for hooks).

A register is either a single file (``lessons.yml``) or a directory of record files
(``lessons/LL-001.md``, see :mod:`homelabnext.registers.records`).  In a directory each file's
front-matter ``id:`` line is the entry id, and the file name must agree with it: ``LL-001.md``
for an allocated id, ``LL-NEW.md`` or ``LL-NEW-<slug>.md`` for a placeholder.  A tombstone is a
record file whose front-matter has a ``retired:`` mapping.  ``resolve`` on a directory rewrites
the placeholder inside the file and renames the file to the allocated id.  A parent commit that
still has the single-file register (the commit before a conversion) is read through the file, so
an entry lost in the conversion itself is caught too.

Retiring an id: an entry whose id was wrong (it collided with another register's meaning, say)
is not deleted.  Its id moves into the register's top-level ``retired:`` mapping, a tombstone,
written in block style (one ``ID:`` key per line, as :func:`retired_in` reads it as text)::

    retired:
      F-02:
        replaced_by: L-07
        reason: meant checklist L-07 (runbook verifies), not F-02 (network segments)

``check_lost`` counts a tombstoned id as present, so the retirement passes CI against the pull
request base; dropping the tombstone later is a loss like any other.  ``duplicates`` refuses an
id that is both live and retired, and ``allocate`` never hands out a retired number, so an old
citation can never silently start meaning something else.  Reusing a retired id on purpose
(an invariants register adopting the checklist's real F-02, say) takes a reviewed diff that
deletes the tombstone in the same change that adds the live entry.

``XX-NEW`` is a valid committed state *on a pull request branch*.  In a project with outside
contributors, ids are allocated once, at merge time, by a maintainer (``hnx ids resolve`` on the
target branch), so two pull requests can never claim the same number.  It is not a valid state of
the main branch: ``hnx ids check-placeholders`` runs on every push to main and fails while any
entry id there is still a placeholder, so a merge that skipped the allocation cannot go unnoticed.

Lock scope: the lock and the high-water mark live under ``git rev-parse --git-common-dir``, so
every worktree of one repository shares them and different repositories never do.  They are
shared between processes of the user who owns that directory; the state directory must be owned
by the current user and not accessible to anyone else (0700), or allocation refuses to run.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import pathlib
import re
import stat
import subprocess
from dataclasses import dataclass

__all__ = [
    "SPECS",
    "IdError",
    "RegisterSpec",
    "allocate",
    "check_lost",
    "dir_problems",
    "discover",
    "duplicates",
    "entry_ids",
    "ids_in",
    "is_record_dir",
    "placeholders",
    "record_id",
    "record_name_problem",
    "resolve_file",
    "retired_in",
    "spec_for",
    "split_entries",
    "state_dir",
    "upstream_refs",
]


class IdError(Exception):
    pass


@dataclass(frozen=True)
class RegisterSpec:
    """How one register kind lays out its entries.

    indent     exact whitespace before an entry's ``- id:`` line (anchoring on it keeps nested
               ``- id:`` keys from splitting a block)
    prefixes   allocatable prefixes
    width      zero padding of the number
    protected  append-only register: a vanished id is corruption (lessons, runbooks,
               invariants). Work-queue registers delete entries legitimately and are unprotected.
    """

    kind: str
    indent: str
    prefixes: tuple[str, ...]
    width: int
    protected: bool
    id_re: str


SPECS: dict[str, RegisterSpec] = {
    "lessons": RegisterSpec("lessons", "", ("LL",), 3, True, r"LL-(?:\d{3,}|NEW)"),
    "runbooks": RegisterSpec("runbooks", "", ("RB",), 3, True, r"RB-(?:\d{3,}|NEW)"),
    "invariants": RegisterSpec(
        "invariants", "", tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 2, True, r"[A-Z]-(?:\d{2,}|NEW)"
    ),
    "queue": RegisterSpec("queue", "", ("PRJ",), 3, False, r"PRJ-(?:\d{3,}(?:\.\d+)?|NEW)"),
}


def spec_for(path: str | os.PathLike) -> RegisterSpec | None:
    """Register kind is taken from the file stem or directory name: lessons.yml, lessons/, ..."""
    return SPECS.get(pathlib.Path(path).stem.split(".")[0])


REGISTER_SUFFIXES = (".yml", ".yaml")
RECORD_SUFFIX = ".md"
_FRONT = re.compile(r"\A---\r?\n(.*?)(?:\r?\n)?^---[ \t]*$", re.S | re.M)
_FM_ID = re.compile(r"(?m)^id:[ \t]*(['\"]?)([^\s'\"#]+)\1[ \t]*(?:#.*)?$")
_FM_RETIRED = re.compile(r"(?m)^retired:")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]*")


def is_record_dir(path: str | os.PathLike) -> bool:
    """A directory register, existing or not (a path without a YAML suffix)."""
    p = pathlib.Path(path)
    return p.is_dir() or (not p.exists() and p.suffix not in REGISTER_SUFFIXES)


def record_id(text: str, spec: RegisterSpec) -> tuple[str | None, bool]:
    """(entry id or None, is a tombstone) read from a record file's front-matter as text."""
    m = _FRONT.match(text)
    if not m:
        return None, False
    fm = m.group(1)
    im = _FM_ID.search(fm)
    ident = im.group(2) if im and re.fullmatch(spec.id_re, im.group(2)) else None
    return ident, bool(_FM_RETIRED.search(fm))


def record_name_problem(name: str, ident: str | None, spec: RegisterSpec) -> str | None:
    """Why a record file's name does not fit its id, or None.  The id is the key; the name
    must agree so that ``[[LL-001]]`` resolves to the file and two files cannot share an id."""
    if not name.endswith(RECORD_SUFFIX):
        return f"{name}: a record file must end in {RECORD_SUFFIX}"
    stem = name[: -len(RECORD_SUFFIX)]
    if ident is None:
        return f"{name}: front-matter has no `id:` that looks like {spec.id_re}"
    if ident.endswith("-NEW"):
        rest = stem[len(ident) + 1 :] if stem.startswith(ident + "-") else None
        if stem == ident or (rest and _SLUG.fullmatch(rest)):
            return None
        return f"{name}: a placeholder record is named {ident}{RECORD_SUFFIX} or {ident}-<slug>.md"
    if stem != ident:
        return f"{name}: file name and front-matter id {ident} disagree (name it {ident}.md)"
    return None


def _dir_ids(texts: dict[str, str], spec: RegisterSpec):
    """([(id, file name)], [tombstoned ids]) of a directory register's record texts."""
    live, retired = [], []
    for name in sorted(texts):
        ident, tomb = record_id(texts[name], spec)
        if ident is None:
            continue
        if tomb:
            retired.append(ident)
        else:
            live.append((ident, name))
    return live, retired


def dir_problems(texts: dict[str, str], spec: RegisterSpec) -> list[str]:
    """Name/id disagreements and allocated ids held by more than one file (or live and retired)."""
    problems, seen = [], {}
    for name in sorted(texts):
        ident, _ = record_id(texts[name], spec)
        bad = record_name_problem(name, ident, spec)
        if bad:
            problems.append(bad)
        if ident is None or ident.endswith("-NEW"):
            continue
        if ident in seen:
            problems.append(f"{name}: id {ident} is also the id of {seen[ident]}")
        else:
            seen[ident] = name
    return problems


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
    """Every id a register accounts for (live and retired) in the working tree or at ``rev``;
    None when the register does not exist there.  A directory register that is missing falls
    back to the single file of the same name (either side of a split or a join)."""
    root = pathlib.Path(root)
    if is_record_dir(root / relpath):
        texts = (
            _disk_dir_texts(root / relpath) if rev is None else _rev_dir_texts(root, rev, relpath)
        )
        if texts is not None:
            live, retired = _dir_ids(texts, spec)
            return {i for i, _ in live} | set(retired)
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


def entry_ids(root, relpath: str, spec: RegisterSpec) -> list[str]:
    """Live entry ids of a working-tree register (file order, or file-name order)."""
    path = pathlib.Path(root) / relpath
    if is_record_dir(path):
        return [i for i, _ in _dir_ids(_disk_dir_texts(path) or {}, spec)[0]]
    return ids_in(path.read_text(), spec) if path.is_file() else []


def discover(root, revs: tuple[str, ...] = ("HEAD",)) -> list[str]:
    """Register paths tracked in the index or present at any of ``revs``: ``*/lessons.yml``-style
    files and the directories that hold ``*/lessons/*.md``-style record files."""
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


STATE_SUBDIR = ("homelabnext", "register_ids")


def state_dir(root=None) -> pathlib.Path:
    """Where lock and high-water files live: ``$HOMELABNEXT_IDS_STATE`` or the git common dir."""
    override = os.environ.get("HOMELABNEXT_IDS_STATE")
    if override:
        return pathlib.Path(override)
    cwd = pathlib.Path(root or os.getcwd())
    out = _git(cwd, "rev-parse", "--git-common-dir")
    if out.returncode:
        raise IdError("not inside a git work tree (the id lock lives in the git common dir)")
    return (cwd / out.stdout.strip()).resolve().joinpath(*STATE_SUBDIR)


def _secure_state_dir(sd: pathlib.Path) -> None:
    """Create ``sd`` 0700, then refuse it unless it is a real directory we own, closed to others."""
    sd.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(sd)
    if not stat.S_ISDIR(st.st_mode):
        raise IdError(f"{sd}: id state path is not a directory (a symlink is refused)")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise IdError(f"{sd}: id state directory is owned by uid {st.st_uid}, not by you")
    if st.st_mode & 0o077:
        raise IdError(
            f"{sd}: id state directory is mode {stat.S_IMODE(st.st_mode):o}; it must be 0700 "
            f"(chmod 700 {sd})"
        )


def _open_nofollow(path: pathlib.Path, flags: int) -> int:
    return os.open(str(path), flags | getattr(os, "O_NOFOLLOW", 0), 0o600)


def _read_hwm(path: pathlib.Path) -> int:
    try:
        fd = _open_nofollow(path, os.O_RDONLY)
    except FileNotFoundError:
        return 0
    except OSError as ex:
        raise IdError(f"{path}: cannot read the high-water mark ({ex})") from ex
    with os.fdopen(fd) as f:
        try:
            return int(f.read().strip() or 0)
        except ValueError:
            return 0  # a torn or garbled mark only loses the cache; the files still set the floor


def _write_hwm(path: pathlib.Path, value: int) -> None:
    """Atomic: write a sibling temp file, fsync, then rename it over the mark."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = _open_nofollow(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(f"{value}\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _anchor(spec: RegisterSpec) -> re.Pattern:
    return re.compile(rf"(?m)^{re.escape(spec.indent)}- id: ({spec.id_re})\s*$")


def split_entries(text: str, spec: RegisterSpec):
    """(header, [(id, block_text)]) - a pure, byte-reversible text split."""
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


def placeholders(text: str, spec: RegisterSpec) -> list[str]:
    """Entry ids that are still ``XX-NEW`` placeholders, in file order (repeats kept).

    Only entry ids count: prose that *mentions* the convention (``write LL-NEW``) is not an id.
    """
    return [i for i in ids_in(text, spec) if i.endswith("-NEW")]


def retired_in(text: str, spec: RegisterSpec) -> list[str]:
    """Ids tombstoned under the top-level ``retired:`` block mapping (read as text).

    Keys are the lines at the block's first indentation level; only keys that look like this
    register's allocated ids count (the schema validator reports any other key).
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
            if rx.fullmatch(key) and not key.endswith("-NEW"):
                found.append(key)
    return sorted(set(found))


def _known(text: str, spec: RegisterSpec) -> set[str]:
    """Every id the file accounts for: live entries plus tombstones."""
    return set(ids_in(text, spec)) | set(retired_in(text, spec))


def _num(ident: str, prefix: str):
    m = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", ident)
    return int(m.group(1)) if m else None


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


def upstream_refs(root) -> list[str]:
    """Refs whose copy of a register bounds the next id: the upstream project's default branch.

    ``upstream/main`` (a fork's conventional name for the project) wins when present; otherwise
    ``origin``'s default branch as recorded in ``refs/remotes/origin/HEAD``, then ``origin/main``
    and ``origin/master``.  Missing refs are skipped, so a fresh clone or a fork works.
    """
    refs = []
    for ref in ("upstream/main", "upstream/master"):
        if _rev_exists(root, ref):
            refs.append(ref)
    head = _git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    if head.returncode == 0 and head.stdout.strip():
        refs.append(head.stdout.strip())
    refs += ["origin/main", "origin/master"]
    return list(dict.fromkeys(r for r in refs if _rev_exists(root, r)))


def allocate(root, relpath: str, prefix: str, count: int = 1) -> list[str]:
    """Claim ``count`` ids atomically across every process of this user on this repository.

    The floor is the max of: the working file, HEAD, the upstream default branch
    (:func:`upstream_refs`), and a high-water mark that records ids a concurrent worktree claimed
    but has not yet committed. A stale cache can only skip numbers (harmless), never reuse one.
    """
    root = pathlib.Path(root)
    spec = spec_for(relpath)
    if spec is None:
        raise IdError(f"{relpath}: unknown register kind ({', '.join(SPECS)})")
    if prefix not in spec.prefixes:
        raise IdError(f"prefix {prefix!r} is not allocatable in {relpath}")
    sd = state_dir(root)
    _secure_state_dir(sd)
    key = relpath.replace("/", "_") + "." + prefix
    lock_path, hwm_path = sd / f"{key}.lock", sd / f"{key}.hwm"
    try:
        fd = _open_nofollow(lock_path, os.O_CREAT | os.O_RDWR)
    except OSError as ex:
        raise IdError(f"{lock_path}: cannot open the id lock ({ex})") from ex
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        floor = 0
        for rev in (None, "HEAD", *upstream_refs(root)):
            if rev is not None and not _rev_exists(root, rev):
                continue
            for ident in _known_at(root, relpath, spec, rev) or ():
                n = _num(ident, prefix)  # a retired number is never handed out again
                if n is not None:
                    floor = max(floor, n)
        floor = max(floor, _read_hwm(hwm_path))
        _write_hwm(hwm_path, floor + count)
        return [f"{prefix}-{n:0{spec.width}d}" for n in range(floor + 1, floor + 1 + count)]
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def resolve_file(root, relpath: str, dry_run: bool = False) -> list[tuple[str, str]]:
    """Replace every ``XX-NEW`` entry id with an allocated one, including self-citations."""
    root = pathlib.Path(root)
    spec = spec_for(relpath)
    if spec is None:
        return []
    path = root / relpath
    if is_record_dir(path):
        return _resolve_dir(root, relpath, spec, dry_run)
    header, blocks = split_entries(path.read_text(), spec)
    assigned, out = [], []
    for ident, block in blocks:
        if not ident.endswith("-NEW"):
            out.append(block)
            continue
        new_id = allocate(root, relpath, ident[:-4], 1)[0]
        out.append(re.sub(rf"\b{re.escape(ident)}\b", new_id, block))
        assigned.append((ident, new_id))
    if assigned and not dry_run:
        path.write_text(header + "".join(out))
    return assigned


def _resolve_dir(root, relpath: str, spec: RegisterSpec, dry_run: bool):
    """Each ``XX-NEW*.md`` record: rewrite its id (and self-citations), rename it ``XX-NNN.md``."""
    d = root / relpath
    assigned = []
    for name, text in sorted((_disk_dir_texts(d) or {}).items()):
        ident, _ = record_id(text, spec)
        if ident is None or not ident.endswith("-NEW"):
            continue
        new_id = allocate(root, relpath, ident[:-4], 1)[0]
        assigned.append((ident, new_id))
        if dry_run:
            continue
        target = d / f"{new_id}{RECORD_SUFFIX}"
        if target.exists():
            raise IdError(f"{relpath}/{target.name} already exists; not overwriting it")
        target.write_text(re.sub(rf"\b{re.escape(ident)}\b", new_id, text))
        (d / name).unlink()
    return assigned


def _rev_exists(root, rev: str) -> bool:
    return _git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}").returncode == 0


def check_lost(
    root, relpath: str, allow: set[str] | None = None, base: str | None = None
) -> list[str]:
    """Ids present in a parent commit but absent from the working file.

    Parents: HEAD, plus MERGE_HEAD / CHERRY_PICK_HEAD / REBASE_HEAD during conflict resolution
    (when the id that vanished came from the OTHER side). With ``base`` (CI: the pull request's
    base commit) that revision is the only parent. ``allow`` or the environment variable
    ``REGISTER_IDS_ALLOW_DROP=ID,ID`` waives a deliberate consolidation.  An id moved into the
    ``retired:`` mapping is still accounted for and is not lost; removing that tombstone is.
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
    waived = set(allow or ()) | {
        s.strip() for s in os.environ.get("REGISTER_IDS_ALLOW_DROP", "").split(",") if s.strip()
    }
    return sorted(parents - now - waived)


def duplicates(text: str, spec: RegisterSpec) -> list[str]:
    """Allocated ids that occur more than once, counting a tombstone as an occurrence (a live
    entry reusing a retired id is a duplicate).  ``XX-NEW`` placeholders may repeat."""
    seen: set[str] = set(retired_in(text, spec))
    dupes: set[str] = set()
    for ident in ids_in(text, spec):
        if ident.endswith("-NEW"):
            continue
        if ident in seen:
            dupes.add(ident)
        seen.add(ident)
    return sorted(dupes)
