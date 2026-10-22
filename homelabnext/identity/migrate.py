# SPDX-License-Identifier: Apache-2.0
"""``hnx records assign-uids``: give every numbered record its uid, once, losslessly.

Records written before ADR-0019 are keyed by a numbered code (``id: LL-001`` in
``lessons/LL-001.md``) or an unmerged placeholder (``LL-NEW``).  For each tree given (a strategy
directory, or a registers directory holding ``lessons/`` and ``runbooks/``) the migration:

1. assigns each record without a ``uid`` a new UUIDv7, in code order within each type, so the
   computed numbers of an unchanged register match the codes it had (``LL-003`` shows as
   ``LL 3``); the strategy record gets one too;
2. rewrites the record's front-matter: ``id`` becomes ``uid`` and ``type``; an objective's
   ``level`` (now its type) and ``measures`` list (now derived from each measure's ``parent``)
   go; a measure's ``objective`` becomes its ``parent``; a requirement's SIRs lose their
   hand-written numbers (``1.1 ...``: they are shown as ``SIR <PIR number>.<n>``);
3. rewrites every reference to a known code as its uid: front-matter links, ``[[CODE]]`` and
   bare mentions in the prose (as ``[[<uid>]]``; a code in a code span is a quotation and stays),
   the values of the record's sidecar events, and every ``--also`` file (records-lane notes,
   customizations, an operator's notes); then regenerates the record's ``## Links`` block;
4. renames ``<CODE>.md`` to ``<uid>.md`` and ``<CODE>.events/`` to ``<uid>.events/``;
5. appends a ``rekey`` event (``by: hnx:migrate``) to every record whose content digest moved
   while one of its reviews was current, so the identity rewrite does not void the reviews;
6. writes ``<tree>/aliases.yml`` (legacy code -> uid; merged with an existing one), through
   which references outside the repository still resolve on read, with a warning.

A tombstone (a file holding only ``id:`` and ``retired: {reason, replaced_by}``: a numbered code
retired before uids so that it would never be reused) gets no uid: a uid is never reused, so
there is nothing left to guard.  Its code moves to the ``retired:`` block of ``aliases.yml``
with its reason and the successor's uid (``replaced_by``), and the file is removed; an old
citation of the code still resolves to the successor (:mod:`.aliases`), and ``check-lost``
counts it as accounted for.

Nothing is written until the whole migration has been computed and checked in memory: every
record still parses, every link it holds resolves to a uid of the trees, every review current
before is current after, and no record is lost.  Re-running is a no-op (a record with a uid is
left alone; a code already rewritten is not found again), so running it twice gives no diff.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import pathlib
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .aliases import ALIASES_FILE, read_aliases, render_aliases
from .types import LEGACY_CODE_RE, TYPE_ORDER
from .uid import UID_PATTERN, is_uid, uuid7

__all__ = ["MigrationError", "Plan", "assign_uids"]

REGISTER_DIRS = {"lessons": "lesson", "runbooks": "runbook"}
STRATEGY_DIRS = ("objectives", "measures", "requirements", "rfis")
_FRONT = re.compile(r"\A---\n(?P<fm>.*?\n)---[ \t]*(?:\n|\Z)", re.S)
_TOP = re.compile(r"^(?P<key>[A-Za-z_][\w-]*):")
_SIR_NUM = re.compile(r"^(?P<lead>\s*-\s+)(?P<q>['\"]?)\d+(?:\.\d+)*\.?\s+")
_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1", re.S)
_LINKS_BLOCK = re.compile(
    r"^## Links[ \t]*\n|<!-- hnx:gen:links -->.*?<!-- /hnx:gen -->", re.S | re.M
)
REKEY_REASON = (
    "hnx records assign-uids: numbered references rewritten as uids (ADR-0019); "
    "the content is otherwise unchanged"
)


class MigrationError(Exception):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__(f"{len(problems)} problem(s)\n  - " + "\n  - ".join(problems))


@dataclasses.dataclass
class Record:
    tree: pathlib.Path
    kind: str  # lessons | runbooks | objectives | ... | strategy
    path: pathlib.Path
    text: str
    fm: dict[str, Any]
    code: str | None  # the legacy id (None for the strategy record)
    uid: str = ""
    new_text: str = ""

    @property
    def tombstone(self) -> bool:
        """A numbered code retired before uids (``id`` + a ``retired`` mapping)."""
        return "retired" in self.fm

    @property
    def rtype(self) -> str:
        if self.kind == "strategy":
            return "strategy"
        if self.kind in REGISTER_DIRS:
            return REGISTER_DIRS[self.kind]
        return str(self.code).rsplit("-", 1)[0] if self.code else str(self.fm.get("type"))


@dataclasses.dataclass
class Plan:
    """What the migration does (or did): ``assigned`` legacy code (or file) -> uid, files
    ``written``, ``renamed`` (old -> new) and ``removed``, the records ``rekeyed``."""

    assigned: dict[str, str] = dataclasses.field(default_factory=dict)
    written: list[pathlib.Path] = dataclasses.field(default_factory=list)
    renamed: list[tuple[pathlib.Path, pathlib.Path]] = dataclasses.field(default_factory=list)
    removed: list[pathlib.Path] = dataclasses.field(default_factory=list)
    rekeyed: list[str] = dataclasses.field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.written or self.renamed or self.removed)


# --- reading ----------------------------------------------------------------------------------


def _front(text: str) -> dict[str, Any] | None:
    import yaml

    m = _FRONT.match(text.replace("\r\n", "\n"))
    if not m:
        return None
    try:
        fm = yaml.safe_load(m["fm"])
    except yaml.YAMLError:
        return None
    return fm if isinstance(fm, dict) else None


def _record_dirs(tree: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    return [(k, tree / k) for k in (*REGISTER_DIRS, *STRATEGY_DIRS) if (tree / k).is_dir()]


def _read_tree(tree: pathlib.Path, problems: list[str]) -> list[Record]:
    if tree.name in (*REGISTER_DIRS, *STRATEGY_DIRS):
        problems.append(f"{tree}: pass the tree (its parent), not one record directory")
        return []
    out: list[Record] = []
    s = tree / "strategy.md"
    if s.is_file():
        text = s.read_text(encoding="utf-8")
        fm = _front(text)
        if fm is None or fm.get("type") != "strategy":
            problems.append(f"{s}: not a strategy record")
        else:
            out.append(Record(tree, "strategy", s, text, fm, None))
    for kind, d in _record_dirs(tree):
        for p in sorted(d.glob("*.md")):
            text = p.read_text(encoding="utf-8")
            fm = _front(text)
            if fm is None:
                problems.append(f"{p}: no YAML front-matter")
                continue
            code = fm.get("id")
            if code is not None and not LEGACY_CODE_RE.fullmatch(str(code)):
                problems.append(f"{p}: id {code!r} is not a numbered record code")
                continue
            out.append(Record(tree, kind, p, text, fm, str(code) if code is not None else None))
    if not out:
        problems.append(f"{tree}: no records (a strategy or a registers directory)")
    return out


def _sort_key(r: Record) -> tuple:
    prefix, _, num = (r.code or "").rpartition("-")
    t = TYPE_ORDER.index(prefix) if prefix in TYPE_ORDER else -1
    return (r.kind != "strategy", t, prefix, num == "NEW", int(num) if num.isdigit() else 0, r.path)


# --- rewriting --------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Codes:
    """The known codes -> uids, and the two patterns that find them: a bare code (a whole
    word: not inside ``XLL-001`` or ``LL-0011``) and, in prose, a code or any ``[[...]]`` link
    (``wiki``: group 1 the link's target, group 2 its ``|alias``; group 3 a bare code)."""

    uids: Mapping[str, str]
    bare: re.Pattern
    wiki: re.Pattern

    @classmethod
    def of(cls, uids: Mapping[str, str]) -> Codes | None:
        if not uids:
            return None
        alt = "(" + "|".join(map(re.escape, sorted(uids, key=len, reverse=True))) + ")"
        return cls(
            dict(uids),
            re.compile(rf"(?<![\w-]){alt}(?![\w-])"),
            re.compile(rf"\[\[([^\]|]*)(\|[^\]]*)?\]\]|(?<![\w-]){alt}(?![\w-])"),
        )


def _sub_codes(text: str, codes: Codes | None) -> str:
    """Every known code as its uid (front-matter values, event files, ``--also`` files)."""
    return codes.bare.sub(lambda m: codes.uids[m[1]], text) if codes else text


def _sub_prose(text: str, codes: Codes | None) -> str:
    """Prose: ``[[CODE]]`` and a bare ``CODE`` become ``[[<uid>]]`` (an alias is kept, as
    written: a code inside it is text, not a second link); a code in a code span is a quotation
    and stays as it is.  One left-to-right pass, so a link is never rewritten inside a link."""
    if codes is None:
        return text

    def one(m: re.Match) -> str:
        if m[3] is not None:
            return f"[[{codes.uids[m[3]]}]]"
        target = codes.uids.get(m[1].strip())
        return f"[[{target}{m[2] or ''}]]" if target else m[0]

    def links(s: str) -> str:
        return codes.wiki.sub(one, s)

    out, pos = [], 0
    for m in _CODE_SPAN.finditer(text):
        out += [links(text[pos : m.start()]), m[0]]
        pos = m.end()
    return "".join(out) + links(text[pos:])


def _fm_lines(fm_text: str) -> list[tuple[str | None, list[str]]]:
    """The front-matter as [(top-level key or None, its lines)], losslessly."""
    blocks: list[tuple[str | None, list[str]]] = []
    for line in fm_text.splitlines(keepends=True):
        m = _TOP.match(line)
        if m or not blocks:
            blocks.append((m["key"] if m else None, [line]))
        else:
            blocks[-1][1].append(line)
    return blocks


def _rewrite_front(r: Record, codes: Codes | None) -> str:
    m = _FRONT.match(r.text.replace("\r\n", "\n"))
    assert m is not None
    out: list[str] = []
    head = [f"uid: {r.uid}\n"]
    if r.kind != "strategy":
        head.append(f"type: {r.rtype}\n")
    placed = False
    for key, lines in _fm_lines(m["fm"]):
        if key in ("id", "uid"):
            if not placed:
                out += head
                placed = True
            continue
        if key == "type" and r.kind != "strategy":
            continue  # written with the uid
        if key in ("level", "measures") and r.kind == "objectives":
            continue  # the type, and the measures' own parent links
        if key == "objective" and r.kind == "measures":
            lines = ["parent:" + lines[0][len("objective:") :], *lines[1:]]
        if key == "sirs":
            lines = [lines[0], *(_SIR_NUM.sub(r"\g<lead>\g<q>", ln) for ln in lines[1:])]
        out += [_sub_codes(ln, codes) for ln in lines]
    if not placed:
        out = head + out
    body = r.text.replace("\r\n", "\n")[m.end() :]
    return "---\n" + "".join(out) + "---\n" + _sub_prose(body, codes)


# --- digests and reviews ----------------------------------------------------------------------


def _events_dir(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(path.stem + ".events")


def _load_entry(text: str, name: str, kind: str, events: list, problems: list[str]):
    from homelabnext.registers import events as ev
    from homelabnext.registers.records import parse_record

    entry = parse_record(text, name, kind, problems, check_name=False)
    if entry is None:
        return None
    return ev.derive(entry, events, kind, problems, name)


def _digest(entry: Mapping[str, Any], kind: str) -> str:
    from homelabnext.registers.records import _canonical
    from homelabnext.registers.schema import record_digest_of

    if kind in REGISTER_DIRS:
        return record_digest_of(_canonical({kind: [dict(entry)]}, kind)[kind][0])
    return record_digest_of({k: v for k, v in entry.items() if k != "values"})


def _current(entry: Mapping[str, Any] | None, digest: str) -> list[dict]:
    if not entry:
        return []
    return [
        r
        for r in entry.get("reviews") or ()
        if isinstance(r, dict)
        and isinstance(r.get("digest"), str)
        and digest.startswith(r["digest"])
    ]


def _rewritten(events: list, texts: Mapping[str, str] | None) -> list:
    """``events`` with the data of each rewritten file (``texts``, by name) re-read."""
    import yaml

    if not texts:
        return list(events)
    return [
        dataclasses.replace(e, data=yaml.safe_load(texts[e.name])) if e.name in texts else e
        for e in events
    ]


# --- the migration ----------------------------------------------------------------------------


def assign_uids(
    trees: Iterable,
    *,
    also: Iterable = (),
    new_uid: Callable[[], str] = uuid7,
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    dry_run: bool = False,
) -> Plan:
    """Migrate ``trees`` (see the module docstring); returns the :class:`Plan` (applied unless
    ``dry_run``).  Fatal (:class:`MigrationError`, nothing written) on anything it cannot do
    losslessly."""
    from homelabnext.registers import events as ev
    from homelabnext.registers.records import refresh_links

    trees = [pathlib.Path(t) for t in trees]
    problems: list[str] = []
    records: list[Record] = []
    known: dict[str, str] = {}  # every code -> uid: earlier migrations' and this one's
    retired: dict[pathlib.Path, dict[str, dict[str, str]]] = {}  # tree -> code -> tombstone
    for t in trees:
        records += _read_tree(t, problems)
        retired[t] = {}
        if (t / ALIASES_FILE).is_file():
            try:
                amap = read_aliases(t / ALIASES_FILE)
            except ValueError as ex:
                problems.append(str(ex))
            else:
                known.update(amap.codes)
                retired[t].update(amap.retired)
    tombstones = [r for r in records if r.tombstone]
    records = [r for r in records if not r.tombstone]
    if problems:
        raise MigrationError(problems)
    plan = Plan()
    todo = [r for r in records if not is_uid(r.fm.get("uid"))]
    seen_codes: dict[str, pathlib.Path] = {}
    for r in sorted(todo, key=_sort_key):
        if r.code and not r.code.endswith("-NEW"):
            if r.code in seen_codes:
                problems.append(f"{r.path}: code {r.code} is also the code of {seen_codes[r.code]}")
                continue
            seen_codes[r.code] = r.path
        r.uid = known.get(r.code or "") or new_uid()
        if r.code and not r.code.endswith("-NEW"):
            known[r.code] = r.uid
            plan.assigned[r.code] = r.uid
        else:
            plan.assigned[str(r.path)] = r.uid
    for r in records:
        if not r.uid:
            r.uid = str(r.fm.get("uid"))
    for r in tombstones:
        retired[r.tree][str(r.code)] = _tombstone(r, known, {**known, **seen_codes}, problems)
    _targets_free(todo, problems)
    if problems:
        raise MigrationError(problems)
    codes = Codes.of(known)
    by_uid = {r.uid: r for r in records}
    events_after: dict[str, dict[str, str]] = {}  # uid -> {event file: new text}
    for r in records:
        r.new_text = _rewrite_front(r, codes) if r in todo else _sub_prose_record(r, codes)
        if r.kind != "strategy":
            r.new_text = refresh_links(r.new_text, r.kind)
        d = _events_dir(r.path)
        if d.is_dir():
            for f in sorted(d.glob("*.yml")):
                text = f.read_text(encoding="utf-8")
                new = _sub_codes(text, codes)
                if new != text:
                    events_after.setdefault(r.uid, {})[f.name] = new
    # check in memory: parse, links, reviews -- before a byte is written
    rekeys: dict[str, dict[str, Any]] = {}
    when = now()
    for r in records:
        kind = r.kind
        name = f"{r.uid}.md" if kind != "strategy" else r.path.name
        ev_before = ev.read_events(_events_dir(r.path), problems, str(r.path))
        before = _load_entry(r.text, r.path.name, kind, ev_before, problems)
        ev_after = _rewritten(ev_before, events_after.get(r.uid))
        after = _load_entry(r.new_text, name, kind, ev_after, problems)
        if before is None or after is None:
            continue
        _links_resolve(r, after, by_uid, problems)
        old, new = _digest(before, kind), _digest(after, kind)
        if old != new and _current(before, old):
            rk = {"event": "rekey", "by": ev.BACKFILL_BY, "date": when.date()}
            rk.update({"from": old, "to": new, "reason": REKEY_REASON})
            problems += [f"{r.path}: {p}" for p in ev.check_event(rk)]
            rekeys[r.uid] = rk
            ev_after.append(ev.Event(ev.event_name(rk, when), rk, ev.stamp_of(when), 1 << 30))
            after = _load_entry(r.new_text, name, kind, ev_after, problems)
        lost = [x for x in _current(before, old) if x not in _keyed(_current(after, new), x)]
        if lost:
            problems.append(f"{r.path}: {len(lost)} current review(s) would not survive")
    if problems:
        raise MigrationError(problems)
    _apply(records, events_after, rekeys, known, trees, also, codes, when, plan, dry_run, retired)
    for r in tombstones:
        plan.removed.append(r.path)
        if not dry_run:
            r.path.unlink()
    return plan


def _tombstone(r: Record, known: Mapping[str, str], live: Mapping[str, Any], problems) -> dict:
    """A pre-uid tombstone as its ``aliases.yml`` ``retired:`` entry (``replaced_by`` mapped to
    the successor's uid); what it cannot carry losslessly is a problem."""
    who = f"{r.path}: tombstone {r.code}"
    ret = r.fm.get("retired")
    text = r.text.replace("\r\n", "\n")
    m = _FRONT.match(text)
    body = _LINKS_BLOCK.sub("", text[m.end() :] if m else text)
    if not r.code or r.code.endswith("-NEW"):
        problems.append(f"{r.path}: a tombstone needs the numbered `id` it retires")
    elif r.code in live:
        problems.append(f"{who} is also the code of {live[r.code]} (a code retired and live)")
    if set(r.fm) - {"id", "retired"} or body.strip():
        problems.append(f"{who}: a tombstone holds only `id` and `retired`")
    if _events_dir(r.path).exists():
        problems.append(f"{who}: has an events directory; a tombstone has no history to carry")
    if not (isinstance(ret, dict) and isinstance(ret.get("reason"), str) and ret["reason"].strip()):
        problems.append(f"{who}: `retired` needs a `reason`")
        return {}
    if set(ret) - {"reason", "replaced_by"}:
        problems.append(f"{who}: `retired` holds only `reason` and `replaced_by`")
    out = {"reason": " ".join(ret["reason"].split())}  # history: quoted as it was written
    rb = ret.get("replaced_by")
    if rb is not None:
        uid = str(rb) if is_uid(rb) and str(rb) in known.values() else known.get(str(rb))
        if uid is None:
            problems.append(f"{who}: replaced_by {rb} names no record of the trees")
        else:
            out["replaced_by"] = uid
    return out


def _targets_free(todo: list[Record], problems: list[str]) -> None:
    """Pre-flight: no record is renamed onto an existing file or events directory (the rename
    would otherwise fail half way through a migration that has already written files)."""
    for r in todo:
        if r.kind == "strategy":
            continue
        target = r.path.with_name(f"{r.uid}.md")
        if target != r.path and target.exists():
            problems.append(f"{target} exists; not overwriting it with {r.path.name}")
        if target != r.path and _events_dir(target).exists():
            problems.append(f"{_events_dir(target)} exists; not overwriting it")


def _keyed(current: list[dict], review: dict) -> list[dict]:
    """``review`` as it is after the migration (its digest may have been carried by a rekey)."""
    same = {k: v for k, v in review.items() if k != "digest"}
    return (
        [review]
        if any({k: v for k, v in c.items() if k != "digest"} == same for c in current)
        else []
    )


def _sub_prose_record(r: Record, codes: Codes | None) -> str:
    """A record that already has its uid: only references to codes (another record migrated
    in this run) are rewritten -- in the front-matter as uids, in the prose as wiki-links."""
    m = _FRONT.match(r.text.replace("\r\n", "\n"))
    if m is None or codes is None:
        return r.text
    body = r.text.replace("\r\n", "\n")[m.end() :]
    return "---\n" + _sub_codes(m["fm"], codes) + "---\n" + _sub_prose(body, codes)


_LINK_FIELDS = ("parent", "supports", "serves", "raised_by", "related", "superseded_by", "lessons")


def _links_resolve(r: Record, entry: Mapping[str, Any], by_uid: Mapping[str, Record], problems):
    """Every record reference of the migrated entry is the uid of a record of the trees."""
    refs: list[str] = []
    for f in _LINK_FIELDS:
        v = entry.get(f)
        refs += [v] if isinstance(v, str) else [x for x in v or () if isinstance(x, str)]
    for ref in entry.get("incorporated_into") or ():
        if isinstance(ref, str) and not ref.startswith("docs/"):
            refs.append(ref.partition("#")[0])
    for st in entry.get("steps") or ():
        refs += [x for x in (st.get("from_lessons") or ()) if isinstance(x, str)]
    for ref in refs:
        if not is_uid(ref):
            problems.append(f"{r.path}: reference {ref} has no uid (no record of the trees has it)")
        elif ref not in by_uid:
            problems.append(f"{r.path}: reference {ref} names no record of the trees")
    for ref in re.findall(rf"\[\[({UID_PATTERN})", r.new_text):
        if ref not in by_uid:
            problems.append(f"{r.path}: wiki-link [[{ref}]] names no record of the trees")


def _apply(records, events_after, rekeys, known, trees, also, codes, when, plan, dry_run, retired):
    from homelabnext.registers import events as ev
    from homelabnext.state import atomic_write_text

    def write(path: pathlib.Path, text: str) -> None:
        plan.written.append(path)
        if not dry_run:
            atomic_write_text(path, text, mode=ev.FILE_MODE)

    for r in records:
        target = r.path if r.kind == "strategy" else r.path.with_name(f"{r.uid}.md")
        if r.new_text != r.text or target != r.path:
            write(target, r.new_text)
        old_ev, new_ev = _events_dir(r.path), _events_dir(target)
        if target != r.path:
            plan.removed.append(r.path)
            if old_ev.is_dir():
                plan.renamed.append((old_ev, new_ev))
            if not dry_run:
                r.path.unlink()
                if old_ev.is_dir():
                    old_ev.rename(new_ev)  # free: checked before anything was written
        live_ev = old_ev if dry_run else new_ev
        for fname, text in events_after.get(r.uid, {}).items():
            plan.written.append(new_ev / fname)
            if not dry_run:
                atomic_write_text(live_ev / fname, text, mode=ev.FILE_MODE)
        if r.uid in rekeys:
            plan.rekeyed.append(r.uid)
            if not dry_run:
                plan.written.append(ev.create_event(new_ev, rekeys[r.uid], when=when))
    for t in trees:
        mine = {c: u for c, u in known.items() if any(r.uid == u and r.tree == t for r in records)}
        if not mine and not retired.get(t):
            continue
        titles = {c: _title(records, u) for c, u in mine.items()}
        text = render_aliases(mine, titles, retired.get(t))
        p = t / ALIASES_FILE
        if not p.is_file() or p.read_text(encoding="utf-8") != text:
            write(p, text)
    for f in also:
        f = pathlib.Path(f)
        files = sorted(x for x in f.rglob("*") if x.is_file()) if f.is_dir() else [f]
        for x in files:
            try:
                text = x.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            new = _sub_codes(text, codes)
            if new != text:
                write(x, new)


def _title(records: list[Record], uid: str) -> str:
    r = next((r for r in records if r.uid == uid), None)
    title = str((r.fm if r else {}).get("title") or "")
    return " ".join(title.split())[:80]
