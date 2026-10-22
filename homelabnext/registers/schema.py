# SPDX-License-Identifier: Apache-2.0
"""Fatal validation for the three registers.

Validation collects every problem and raises one RegisterError listing all of them, so an
author fixes a register in one pass. A render that cannot be trusted must not happen at all.

Lesson model (root-cause analysis): a *contributing factor* enabled the problem; the *root
cause* is why that condition existed. A control must change what is possible or detectable;
"be careful" is not one. Every pitfall carries a falsifiable verification: an observable and
the result that would prove the control is NOT working.

Lessons have a ``kind`` and a lifecycle, because a lesson is backlog (knowledge not yet built
into the system), not a permanent record:

* ``pitfall`` (a negative lesson): open -> partial -> controlled -> retired.  ``controlled``
  carries ``review_by``; ``retired`` needs ``retired_by`` (the invariant, test or gate that makes
  recurrence impossible or loudly detectable) and ``retired_on``.
* ``practice`` (a method that works): active -> incorporated | superseded | retired.  It names
  what it ``applies_to`` and carries ``review_by`` while active; ``incorporated`` needs
  ``incorporated_into`` (a runbook, optionally a step, or a docs/systems page), ``superseded``
  needs ``superseded_by``, ``retired`` needs ``retired_reason`` and ``retired_on``.

Every lesson and runbook is identified by its ``uid`` (a UUIDv7, ADR-0019) and carries its
``type``; every reference to another record is a uid, and the number a record is shown with
(``LL 3``) is computed, never stored (:mod:`homelabnext.identity.numbers`).  Every lesson and
runbook has ``last_reviewed``.  Retired, incorporated and superseded lessons, and runbooks with
``superseded_by``, stay (their uids are cited) but are inactive (:func:`is_active`).  :func:`check_links` resolves every reference across records and into the
repository (fatal); :func:`sync_warnings` reports an incorporation the runbook does not cite back.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import re
from collections.abc import Iterable

from homelabnext.identity import UID_PATTERN, is_uid, label_map, node_of, order_problems

__all__ = [
    "INACTIVE_STATUSES",
    "LESSON_KINDS",
    "LESSON_STATUSES",
    "PITFALL_STATUSES",
    "PRACTICE_STATUSES",
    "WEAK_PHRASES",
    "RegisterError",
    "check_links",
    "is_active",
    "labels_of",
    "record_digest_of",
    "sync_warnings",
    "validate_invariants",
    "validate_lessons",
    "validate_runbooks",
]


class RegisterError(Exception):
    def __init__(self, register: str, problems: list[str]):
        self.register, self.problems = register, problems
        super().__init__(f"{register}: {len(problems)} problem(s)\n  - " + "\n  - ".join(problems))


LESSON_KINDS = ("pitfall", "practice")
# pitfalls graduate into mechanisms (retired_by), practices into procedures (incorporated_into)
PITFALL_STATUSES = ("open", "partial", "controlled", "retired")
PRACTICE_STATUSES = ("active", "incorporated", "superseded", "retired")
LESSON_STATUSES = PITFALL_STATUSES + PRACTICE_STATUSES[:3]
INACTIVE_STATUSES = frozenset({"retired", "incorporated", "superseded"})
LESSON_COMMON = frozenset(
    {"uid", "type", "order", "title", "kind", "status", "date", "systems", "author", "reviews"}
    | {"review_by", "related", "notes", "last_verified"}
)
PITFALL_FIELDS = frozenset(
    {"recurrences", "symptom", "contributing_factor", "root_cause", "preventive_control"}
    | {"verification", "open_reason", "retired_by", "retired_on"}
)
PRACTICE_FIELDS = frozenset(
    {"applies_to", "method", "rationale", "verification", "incorporated_into", "superseded_by"}
    | {"retired_on", "retired_reason"}
)
RUNBOOK_FIELDS = frozenset(
    {"uid", "type", "order", "title", "purpose", "systems", "steps", "author", "reviews"}
    | {"review_by", "superseded_by", "related", "lessons", "last_verified"}
)
#: the record type each register holds (its entries' ``type``)
RECORD_TYPE = {"lessons": "lesson", "runbooks": "runbook"}
# criterion ids are docs/checklist.md row ids, chosen to match a row (never allocated)
CRIT_ID = re.compile(r"^[A-Z]-\d{2,}$")
CRIT_REF = re.compile(r"^[A-Z]-\d{2,}$")
# retired_by: an invariant id, a repository path (a test, a lint) or a make target (a gate)
MECHANISM_REF = re.compile(r"^(?:[A-Z]-\d{2,}|make:[A-Za-z0-9_.-]+|[\w.-]+(?:/[\w.-]+)+)$")
MECHANISM_WHAT = "an invariant id (M-17), a repository path (tests/x/test_y.py) or make:<target>"
# incorporated_into: a runbook (optionally one step) or a system page's human block
RUNBOOK_REF_RX = re.compile(rf"^{UID_PATTERN}(?:#\d+)?$")
DESTINATION_REF = re.compile(
    rf"^(?:{UID_PATTERN}(?:#[1-9]\d*)?|docs/systems/[a-z0-9._-]+\.md(?:#(?:use|verify|failure))?)$"
)
DESTINATION_WHAT = (
    "a runbook's uid (<uid>, <uid>#2 for step 2) or docs/systems/<service>.md[#use|verify|failure]"
)
LEGACY_CODE = re.compile(r"^(?:LL|RB)-(?:\d{3,}|NEW)(?:#\d+)?$")
LEGACY_HINT = "a legacy numbered code; records refer to each other by uid (hnx records assign-uids)"
MIN_TEXT = 12  # chars; a one-word root cause is a label, not a cause
WEAK_PHRASES = (
    "be careful",
    "human error",
    "operator error",
    "user error",
    "pay attention",
    "read the docs",
    "remember to",
    "try harder",
    "be more careful",
    "wasn't careful",
)
UNFALSIFIABLE = ("looks fine", "seems ok", "should work", "probably", "manual inspection")


def _text(e, key, problems, who, min_len=MIN_TEXT):
    v = e.get(key)
    if not isinstance(v, str) or len(v.strip()) < min_len:
        problems.append(f"{who}: `{key}` is missing or too short (< {min_len} chars)")
        return ""
    return v


def _weak(v: str) -> str | None:
    low = v.lower()
    return next((p for p in WEAK_PHRASES if p in low), None)


def _date(v) -> bool:
    if isinstance(v, dt.date):
        return True
    try:
        dt.date.fromisoformat(str(v))
        return True
    except ValueError:
        return False


def _entries(data, key, register):
    if not isinstance(data, dict) or not isinstance(data.get(key), list) or not data[key]:
        raise RegisterError(
            register, [f"top level must be a mapping with a non-empty `{key}:` list"]
        )
    return data[key]


def _dupes(ids, problems, what="id"):
    seen = set()
    for i in ids:
        if i in seen:
            problems.append(f"duplicate {what} {i}")
        seen.add(i)


def labels_of(entries: Iterable[dict]) -> dict[str, str]:
    """uid -> display label (``LL 3``) of a register's loaded entries."""
    return label_map(node_of(e) for e in entries if isinstance(e, dict) and is_uid(e.get("uid")))


def _who(e, labels: dict[str, str]) -> str:
    """How a problem names a record: its display label and its uid (``LL 3 <uid>``)."""
    uid = str(e.get("uid", "<no uid>"))
    return f"{labels[uid]} {uid}" if uid in labels else uid


def _uid_ref(x, what: str) -> str | None:
    """Why ``x`` is not a uid reference, or None."""
    if is_uid(x):
        return None
    if isinstance(x, str) and LEGACY_CODE.match(x):
        return f"{what} {x!r} is {LEGACY_HINT}"
    return f"{what} {x!r} is not a uid"


def _identity(e, who, kind, problems):
    """``uid`` (canonical UUIDv7), ``type`` (the register's), ``order`` (a number, if any)."""
    if "uid" not in e and "id" in e:
        problems.append(f"{who}: numbered `id: {e['id']}` and no `uid`; {LEGACY_HINT}")
    elif not is_uid(e.get("uid")):
        problems.append(f"{who}: `uid` must be a canonical UUIDv7 (lowercase, version 7)")
    if e.get("type") != RECORD_TYPE[kind]:
        problems.append(f"{who}: `type` must be {RECORD_TYPE[kind]}, not {e.get('type')!r}")
    o = e.get("order")
    if o is not None and (isinstance(o, bool) or not isinstance(o, int | float)):
        problems.append(f"{who}: `order` must be a number (the sort key among its siblings)")
    if "parent" in e:
        problems.append(f"{who}: a {RECORD_TYPE[kind]} has no parent (registers are flat)")


def _related(e, who, problems):
    """Optional ``related:``: typed links to other lessons/runbooks (resolved by check_related)."""
    rel = e.get("related")
    if rel is None:
        return
    if not (isinstance(rel, list) and all(isinstance(x, str) for x in rel)):
        problems.append(f"{who}: `related` must be a list of uids")
        return
    for x in rel:
        if bad := _uid_ref(x, "related"):
            problems.append(f"{who}: {bad}")
        elif x == e.get("uid"):
            problems.append(f"{who}: related names the entry itself")
    if len(set(rel)) != len(rel):
        problems.append(f"{who}: `related` repeats a uid")


def _lessons(e, who, problems):
    """A runbook's optional ``lessons:``: the lessons it was written from, by uid (runbook
    schema 2.1; resolved to live lessons by check_links)."""
    v = e.get("lessons")
    if v is None:
        return
    if not (isinstance(v, list) and v and all(isinstance(x, str) for x in v)):
        problems.append(f"{who}: `lessons` must be a non-empty list of lesson uids")
        return
    for x in v:
        if bad := _uid_ref(x, "lessons"):
            problems.append(f"{who}: {bad}")
    if len(set(v)) != len(v):
        problems.append(f"{who}: `lessons` repeats a uid")


def _ref_list(e, key, who, problems, rx: re.Pattern, what: str) -> list[str]:
    v = e.get(key)
    if not (isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)):
        problems.append(f"{who}: `{key}` must be a non-empty list of {what}")
        return []
    for x in v:
        if LEGACY_CODE.match(x):
            problems.append(f"{who}: {key} {x!r} is {LEGACY_HINT}")
        elif not rx.match(x):
            problems.append(f"{who}: {key} {x!r} is not {what}")
    return v


def _lifecycle_dates(e, who, problems, *, review_required: bool):
    """``review_by``: when the record must next be looked at (``last_reviewed`` is derived from
    the reviews, see homelabnext.reviews)."""
    rb = e.get("review_by")
    if rb is None:
        if review_required:
            problems.append(
                f"{who}: `review_by` (ISO date) is required for status {e.get('status')}"
            )
    elif not _date(rb):
        problems.append(f"{who}: `review_by` must be ISO YYYY-MM-DD")


# about the record, not its content: its identity (uid; the numbered id of a record written before
# uids), a review or a verification run never makes reviews stale, and neither does `order` (where
# it sorts among its siblings: moving a record changes its shown number, not what it says)
NOT_CONTENT = frozenset({"id", "uid", "order", "reviews", "last_verified"})
SELF = "<this record>"


def _self_neutral(v, rx: re.Pattern):
    """``v`` with every citation of the record's own numbered id replaced by one token: how a
    record written before uids was digested (allocating ``LL-NEW`` -> ``LL-006`` was no edit),
    kept so the uid migration can prove which reviews were current (``rekey`` events)."""
    if isinstance(v, str):
        return rx.sub(SELF, v)
    if isinstance(v, list):
        return [_self_neutral(x, rx) for x in v]
    if isinstance(v, dict):
        return {k: _self_neutral(x, rx) for k, x in v.items()}
    return v


def record_digest_of(entry: dict) -> str:
    """The content digest a review of this record carries: every field but its identity
    (``uid``), ``order``, ``reviews`` and ``last_verified`` (a recurrence or a status change does
    count).  A record written before uids is digested as it always was (its own numbered ``id``
    left out and neutralized where it cites itself), so the migration can compare."""
    from homelabnext.reviews import content_digest

    body = {k: v for k, v in entry.items() if k not in NOT_CONTENT}
    own = str(entry.get("id") or "")
    if own:
        body = _self_neutral(body, re.compile(rf"\b{re.escape(own)}\b(?!-)"))
    return content_digest(body)


def review_evaluation(e, artefact: str = "", state: str = "", policy=None, who: str = ""):
    """:func:`homelabnext.reviews.evaluate` of a loaded record (its derived ``reviews``) against
    its content digest: the one judgement the validation, the due list and the graph share."""
    from homelabnext.reviews import evaluate

    return evaluate(
        e.get("reviews"),
        author=e.get("author"),
        digest=record_digest_of(e),
        artefact=artefact,
        state=state,
        policy=policy,
        who=who,
    )


def _reviews(e, who, artefact, state, policy, problems, require=True):
    from homelabnext.reviews import missing_message

    digest = record_digest_of(e)
    ev = review_evaluation(e, artefact, state, policy, who)
    problems += ev.problems
    if ev.missing and require:
        problems.append(missing_message(who, state, ev, digest))


def _as_date(v) -> dt.date:
    return v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))


def _only_when(e, who, problems, fields, cond: bool, when: str):
    for f in fields:
        if f in e and not cond:
            problems.append(f"{who}: `{f}` only belongs on {when}")


def is_active(entry: dict, register: str = "lessons") -> bool:
    """False for a record that has graduated or been replaced: a retired, incorporated or
    superseded lesson, a runbook with ``superseded_by``.  Inactive records stay as files (their
    ids are cited) but the graph, context packs and indexes skip or archive them."""
    if register == "runbooks":
        return not entry.get("superseded_by")
    return entry.get("status") not in INACTIVE_STATUSES


def _repo_targets(root: pathlib.Path) -> set[str]:
    mk = root / "Makefile"
    if not mk.is_file():
        return set()
    return set(re.findall(r"(?m)^([A-Za-z0-9_.-]+)[ \t]*:(?!=)", mk.read_text()))


def check_links(lessons, runbooks, criteria=None, root=None) -> None:
    """Every cross-record and outward reference resolves (fatal; validated lists in).

    ``related``, ``superseded_by``, a runbook's ``lessons`` and step ``from_lessons`` name live
    records (by uid);
    ``incorporated_into`` names a runbook (and step) or a ``docs/systems/`` page that exists;
    ``retired_by`` names a live invariant of ``criteria`` (ids), a file under ``root`` or a
    ``make:<target>`` of root's Makefile.
    """
    root = pathlib.Path(root or ".")
    ll = {str(e["uid"]): e for e in lessons}
    rb = {str(e["uid"]): e for e in runbooks}
    labels = {**labels_of(lessons), **labels_of(runbooks)}
    live = set(ll) | set(rb)
    targets = None
    problems = []
    for reg in (lessons, runbooks):
        for e in reg:
            problems += [
                f"{_who(e, labels)}: related {x} is not a lesson or runbook"
                for x in e.get("related") or ()
                if x not in live
            ]
    for e in lessons:
        who = _who(e, labels)
        sb = e.get("superseded_by")
        if sb and (sb not in ll or ll[sb].get("kind") != "practice"):
            problems.append(f"{who}: superseded_by {sb} is not a practice in this register")
        for ref in e.get("incorporated_into") or ():
            path, _, anchor = ref.partition("#")
            if RUNBOOK_REF_RX.match(ref):
                if path not in rb:
                    problems.append(f"{who}: incorporated_into {ref}: no runbook {path}")
                elif anchor and int(anchor) > len(rb[path].get("steps") or ()):
                    problems.append(f"{who}: incorporated_into {ref}: {path} has no step {anchor}")
            elif not (root / path).is_file():
                problems.append(f"{who}: incorporated_into {ref}: {path} does not exist")
        for ref in e.get("retired_by") or ():
            if CRIT_REF.match(ref):
                if criteria is None:
                    problems.append(
                        f"{who}: retired_by {ref}: no invariants register to resolve it"
                    )
                elif ref not in criteria:
                    problems.append(f"{who}: retired_by {ref} is not a live invariant")
            elif ref.startswith("make:"):
                targets = _repo_targets(root) if targets is None else targets
                if ref[5:] not in targets:
                    problems.append(f"{who}: retired_by {ref}: no such Makefile target")
            elif not (root / ref).is_file():
                problems.append(f"{who}: retired_by {ref}: {ref} does not exist")
    for e in runbooks:
        sb = e.get("superseded_by")
        if sb and sb not in rb:
            problems.append(
                f"{_who(e, labels)}: superseded_by {sb} is not a runbook in this register"
            )
        for x in e.get("lessons") or ():
            if x not in ll:
                problems.append(f"{_who(e, labels)}: lessons {x} is not a lesson")
        for n, st in enumerate(e.get("steps") or (), 1):
            for x in st.get("from_lessons") or ():
                if x not in ll:
                    problems.append(f"{_who(e, labels)} step {n}: from_lessons {x} is not a lesson")
    if problems:
        raise RegisterError("links", problems)


def sync_warnings(lessons, runbooks) -> list[str]:
    """Practices incorporated into a runbook the runbook does not cite back (``from_lessons``)."""
    rb = {str(e["uid"]): e for e in runbooks}
    labels = {**labels_of(lessons), **labels_of(runbooks)}
    out = []
    for e in lessons:
        for ref in e.get("incorporated_into") or ():
            path, _, anchor = ref.partition("#")
            if path not in rb:
                continue
            steps = rb[path].get("steps") or []
            pick = [steps[int(anchor) - 1]] if anchor and int(anchor) <= len(steps) else steps
            if not any(e["uid"] in (st.get("from_lessons") or ()) for st in pick):
                name = labels.get(path, path)
                where = f"step {anchor} of {name}" if anchor else f"any step of {name}"
                out.append(
                    f"{labels.get(e['uid'], e['uid'])} is incorporated into {name}"
                    f"{'#' + anchor if anchor else ''} but {where} does not cite it back "
                    f"(add `- from_lessons: [[{e['uid']}]]`)"
                )
    return out


def _retired(data, live, id_rx: re.Pattern, problems: list[str]) -> dict:
    """The invariants' optional top-level ``retired:`` mapping of tombstoned criterion ids (see
    registers.ids): {ID: {reason: why it was retired, replaced_by: live ID or omitted}}.  A
    tombstone may not name a live id (that is reuse) and may only point at an id that is live.
    """
    ret = data.get("retired") if isinstance(data, dict) else None
    if ret is None:
        return {}
    if not isinstance(ret, dict):
        problems.append("`retired` must be a mapping of id -> {reason, replaced_by}")
        return {}
    live = set(live)
    for k, v in ret.items():
        who = f"retired {k}"
        if not id_rx.match(str(k)):
            problems.append(f"{who}: is not a criterion id")
        if str(k) in live:
            problems.append(f"{who}: is also a live entry (delete the tombstone to reuse it)")
        if not isinstance(v, dict):
            problems.append(f"{who}: must be a mapping with `reason` (and `replaced_by`)")
            continue
        extra = set(v) - {"reason", "replaced_by"}
        if extra:
            problems.append(f"{who}: unknown field(s) {sorted(extra)}")
        _text(v, "reason", problems, who)
        rb = v.get("replaced_by")
        if rb is not None and str(rb) not in live:
            problems.append(f"{who}: replaced_by {rb} is not a live entry")
    return ret


def _pitfall(e, who, status, problems):
    if status not in PITFALL_STATUSES:
        problems.append(f"{who}: a pitfall's `status` must be one of {PITFALL_STATUSES}")
    r = e.get("recurrences")
    if not (isinstance(r, int) and not isinstance(r, bool) and r >= 0):
        problems.append(f"{who}: `recurrences` must be an integer >= 0")
    _text(e, "symptom", problems, who)
    _text(e, "contributing_factor", problems, who)
    rc = _text(e, "root_cause", problems, who)
    if rc and (w := _weak(rc)):
        problems.append(f"{who}: root_cause is a person/behaviour ({w!r}); go one level deeper")
    pc = e.get("preventive_control")
    if pc is None and status == "open":
        if not isinstance(e.get("open_reason"), str) or len(e["open_reason"].strip()) < MIN_TEXT:
            problems.append(f"{who}: status open without a control needs `open_reason`")
    else:
        pct = _text(e, "preventive_control", problems, who)
        if pct and (w := _weak(pct)):
            problems.append(
                f"{who}: preventive_control is exhortation ({w!r}); a control changes "
                "what is possible or detectable"
            )
    v = e.get("verification")
    if not isinstance(v, dict):
        if not (status == "open" and pc is None):
            problems.append(
                f"{who}: `verification` must be a mapping with `observable` and `expected`"
            )
    else:
        _verification(v, who, problems)
    if status == "controlled" and isinstance(v, dict) and not e.get("preventive_control"):
        problems.append(f"{who}: controlled needs a preventive_control")
    # graduation: a retired pitfall names the permanent mechanism that replaced it
    if status == "retired":
        _ref_list(e, "retired_by", who, problems, MECHANISM_REF, MECHANISM_WHAT)
        if not _date(e.get("retired_on")):
            problems.append(f"{who}: status retired needs `retired_on` (ISO date)")
    elif "retired_by" in e:
        if status != "controlled":
            problems.append(
                f"{who}: `retired_by` belongs on a controlled (candidate) or retired pitfall"
            )
        else:
            _ref_list(e, "retired_by", who, problems, MECHANISM_REF, MECHANISM_WHAT)
    _only_when(e, who, problems, ("retired_on",), status == "retired", "a retired pitfall")
    _lifecycle_dates(e, who, problems, review_required=status == "controlled")
    return "lesson.pitfall"


def _practice(e, who, status, problems):
    if status not in PRACTICE_STATUSES:
        problems.append(f"{who}: a practice's `status` must be one of {PRACTICE_STATUSES}")
    a = e.get("applies_to")
    if not (isinstance(a, list) and a and all(isinstance(x, str) and x for x in a)):
        problems.append(
            f"{who}: `applies_to` must name the technologies, products, versions or systems "
            "the practice holds for (a non-empty list)"
        )
    _text(e, "method", problems, who)
    if isinstance(e.get("verification"), dict):
        _verification(e["verification"], who, problems)
    elif "verification" in e:
        problems.append(f"{who}: `verification` must be a mapping with `observable` and `expected`")
    if status == "incorporated":
        _ref_list(e, "incorporated_into", who, problems, DESTINATION_REF, DESTINATION_WHAT)
    if status == "superseded":
        sb = e.get("superseded_by")
        if not isinstance(sb, str) or (bad := _uid_ref(sb, "superseded_by")):
            why = bad if isinstance(sb, str) else "status superseded needs `superseded_by`"
            problems.append(f"{who}: {why} (the uid of the practice that replaced it)")
        elif sb == e.get("uid"):
            problems.append(f"{who}: superseded_by names the entry itself")
    if status == "retired":
        _text(e, "retired_reason", problems, who)
        if not _date(e.get("retired_on")):
            problems.append(f"{who}: status retired needs `retired_on` (ISO date)")
    _only_when(
        e,
        who,
        problems,
        ("incorporated_into",),
        status == "incorporated",
        "an incorporated practice",
    )
    _only_when(
        e, who, problems, ("superseded_by",), status == "superseded", "a superseded practice"
    )
    _only_when(
        e,
        who,
        problems,
        ("retired_on", "retired_reason"),
        status == "retired",
        "a retired practice",
    )
    _lifecycle_dates(e, who, problems, review_required=status == "active")
    return "lesson.practice"


def _verification(v, who, problems):
    obs = _text(v, "observable", problems, f"{who}.verification", 6)
    exp = _text(v, "expected", problems, f"{who}.verification", 3)
    for txt in (obs, exp):
        if txt and any(u in txt.lower() for u in UNFALSIFIABLE):
            problems.append(f"{who}: verification is not falsifiable ({txt!r})")


def validate_lessons(data, policy=None, *, require_reviews: bool = True) -> list[dict]:
    """Fatal.  With a review ``policy`` (homelabnext.reviews.Policy) each lesson's status must
    also carry the reviews the policy requires, current with its content (unless
    ``require_reviews`` is false: the write path, where a later review event pays that debt)."""
    items = _entries(data, "lessons", "lessons")
    problems: list[str] = []
    _common(data, items, "lessons", problems)
    labels = labels_of(items)
    for e in items:
        if not isinstance(e, dict):
            problems.append(f"entry is not a mapping: {e!r}")
            continue
        who = _who(e, labels)
        _identity(e, who, "lessons", problems)
        kind = e.get("kind")
        if kind not in LESSON_KINDS:
            problems.append(
                f"{who}: `kind` must be one of {LESSON_KINDS} (pitfall: a problem with a root "
                "cause and a control; practice: a method that works)"
            )
            continue
        extra = set(e) - LESSON_COMMON - (PITFALL_FIELDS if kind == "pitfall" else PRACTICE_FIELDS)
        if extra:
            problems.append(f"{who}: unknown field(s) for a {kind} {sorted(extra)}")
        _text(e, "title", problems, who, 4)
        _related(e, who, problems)
        if not _date(e.get("date")):
            problems.append(f"{who}: `date` must be ISO YYYY-MM-DD")
        s = e.get("systems")
        if not (isinstance(s, list) and s and all(isinstance(x, str) and x for x in s)):
            problems.append(f"{who}: `systems` must be a non-empty list of strings")
        art = (_pitfall if kind == "pitfall" else _practice)(e, who, e.get("status"), problems)
        _reviews(e, who, art, str(e.get("status")), policy, problems, require_reviews)
    if problems:
        raise RegisterError("lessons", problems)
    return items


def validate_runbooks(data, policy=None, *, require_reviews: bool = True) -> list[dict]:
    items = _entries(data, "runbooks", "runbooks")
    problems: list[str] = []
    _common(data, items, "runbooks", problems)
    labels = labels_of(items)
    for e in items:
        if not isinstance(e, dict):
            problems.append(f"entry is not a mapping: {e!r}")
            continue
        who = _who(e, labels)
        _identity(e, who, "runbooks", problems)
        extra = set(e) - RUNBOOK_FIELDS
        if extra:
            problems.append(f"{who}: unknown field(s) {sorted(extra)}")
        _text(e, "title", problems, who, 4)
        _related(e, who, problems)
        _lessons(e, who, problems)
        _text(e, "purpose", problems, who)
        _lifecycle_dates(e, who, problems, review_required=not e.get("superseded_by"))
        _reviews(
            e,
            who,
            "runbook",
            "superseded" if e.get("superseded_by") else "active",
            policy,
            problems,
            require_reviews,
        )
        sb = e.get("superseded_by")
        if sb is not None and (not isinstance(sb, str) or _uid_ref(sb, "") or sb == e.get("uid")):
            why = _uid_ref(sb, "superseded_by") if isinstance(sb, str) else None
            problems.append(
                f"{who}: superseded_by must be another runbook's uid" + (f" ({why})" if why else "")
            )
        s = e.get("systems")
        if not (isinstance(s, list) and s and all(isinstance(x, str) and x for x in s)):
            problems.append(f"{who}: `systems` must be a non-empty list of strings")
        steps = e.get("steps")
        if not (isinstance(steps, list) and steps):
            problems.append(f"{who}: `steps` must be a non-empty list")
            continue
        for n, st in enumerate(steps, 1):
            if not isinstance(st, dict) or not str(st.get("do", "")).strip():
                problems.append(f"{who} step {n}: needs `do`")
                continue
            if not str(st.get("verify", "")).strip():
                problems.append(f"{who} step {n}: every step needs its own `verify`")
            extra = set(st) - {"do", "verify", "from_lessons"}
            if extra:
                problems.append(f"{who} step {n}: unknown field(s) {sorted(extra)}")
            fl = st.get("from_lessons")
            if fl is not None and not (
                isinstance(fl, list) and fl and all(isinstance(x, str) and is_uid(x) for x in fl)
            ):
                legacy = [x for x in fl or () if isinstance(x, str) and LEGACY_CODE.match(x)]
                why = f" ({', '.join(legacy)}: {LEGACY_HINT})" if legacy else ""
                problems.append(
                    f"{who} step {n}: `from_lessons` must be a list of lesson uids{why}"
                )
    if problems:
        raise RegisterError("runbooks", problems)
    return items


def _common(data, items, kind: str, problems: list[str]) -> None:
    """What spans a register's records: unique uids, unique ``order`` among siblings, and no
    top-level key but the record list (the per-id ``retired:`` block of the numbered registers
    is gone: a uid is never reused, so there is nothing to tombstone)."""
    good = [e for e in items if isinstance(e, dict)]
    _dupes([str(e.get("uid")) for e in good if is_uid(e.get("uid"))], problems, "uid")
    extra = set(data) - {kind} if isinstance(data, dict) else set()
    if extra:
        problems.append(f"top level: unknown key(s) {sorted(extra)} (only `{kind}:`)")
    labels = labels_of(good)
    nodes = [node_of(e) for e in good if is_uid(e.get("uid"))]
    problems += order_problems(nodes, labels)


def validate_invariants(data) -> dict:
    items = _entries(data, "criteria", "invariants")
    problems: list[str] = []
    pillars = data.get("pillars") or []
    letters = set()
    for p in pillars:
        if (
            not isinstance(p, dict)
            or not re.fullmatch(r"[A-Z]", str(p.get("letter", "")))
            or not str(p.get("title", "")).strip()
        ):
            problems.append(f"bad pillar {p!r}: needs `letter` (A-Z) and `title`")
        else:
            letters.add(p["letter"])
    _dupes([str(e.get("id")) for e in items if isinstance(e, dict)], problems)
    retired = _retired(
        data, [str(e.get("id")) for e in items if isinstance(e, dict)], CRIT_ID, problems
    )
    for e in items:
        if not isinstance(e, dict):
            problems.append(f"entry is not a mapping: {e!r}")
            continue
        who = str(e.get("id", "<no id>"))
        if not CRIT_ID.match(who):
            problems.append(f"{who}: id must look like X-01")
        elif letters and who[0] not in letters:
            problems.append(f"{who}: pillar {who[0]} is not declared in `pillars`")
        _text(e, "statement", problems, who)
        ev = e.get("evidence")
        if ev not in ("auto", "plugin", "manual", "server"):
            problems.append(f"{who}: `evidence` must be auto|plugin|manual|server")
        if ev == "auto":
            _text(e, "observable", problems, who, 2)
            _text(e, "expected", problems, who, 2)
        elif ev == "plugin":
            _text(e, "plugin", problems, who, 2)
        elif ev in ("manual", "server"):
            _text(e, "observable", problems, who, 6)
            if e.get("deferred") and len(str(e.get("why", "")).strip()) < MIN_TEXT:
                problems.append(f"{who}: deferred criteria need a `why`")
        if "expect_regex" in e:
            try:
                re.compile(e["expect_regex"])
            except re.error as ex:
                problems.append(f"{who}: expect_regex does not compile ({ex})")
        _text(e, "remediation", problems, who)
    if problems:
        raise RegisterError("invariants", problems)
    return {"pillars": pillars, "criteria": items, "retired": retired}
