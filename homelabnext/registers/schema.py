# SPDX-License-Identifier: Apache-2.0
"""Fatal validation for the three registers.

Validation collects every problem and raises one RegisterError listing all of them, so an
author fixes a register in one pass. A render that cannot be trusted must not happen at all.

Lesson model (root-cause analysis): a *contributing factor* enabled the problem; the *root
cause* is why that condition existed. A control must change what is possible or detectable;
"be careful" is not one. Every lesson carries a falsifiable verification: an observable and
the result that would prove the control is NOT working.
"""

from __future__ import annotations

import datetime as dt
import re

__all__ = [
    "LESSON_STATUSES",
    "WEAK_PHRASES",
    "RegisterError",
    "check_related",
    "validate_invariants",
    "validate_lessons",
    "validate_runbooks",
]


class RegisterError(Exception):
    def __init__(self, register: str, problems: list[str]):
        self.register, self.problems = register, problems
        super().__init__(f"{register}: {len(problems)} problem(s)\n  - " + "\n  - ".join(problems))


LESSON_STATUSES = ("open", "partial", "controlled")
# ``XX-NEW`` is a valid committed state: a maintainer allocates the number at merge time.
LESSON_ID = re.compile(r"^LL-(?:\d{3,}|NEW)$")
RUNBOOK_ID = re.compile(r"^RB-(?:\d{3,}|NEW)$")
CRIT_ID = re.compile(r"^[A-Z]-(?:\d{2,}|NEW)$")
RECORD_REF = re.compile(
    r"^(?:LL|RB)-\d{3,}$"
)  # a `related:` target: an allocated lesson or runbook
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


def _dupes(ids, problems):
    seen = set()
    for i in ids:
        if i.endswith("-NEW"):
            continue  # placeholders may repeat until allocated
        if i in seen:
            problems.append(f"duplicate id {i}")
        seen.add(i)


def _related(e, who, problems):
    """Optional ``related:``: typed links to other lessons/runbooks (resolved by check_related)."""
    rel = e.get("related")
    if rel is None:
        return
    if not (isinstance(rel, list) and all(isinstance(x, str) for x in rel)):
        problems.append(f"{who}: `related` must be a list of ids (LL-001, RB-002)")
        return
    for x in rel:
        if not RECORD_REF.match(x):
            problems.append(f"{who}: related {x!r} is not an allocated lesson or runbook id")
        elif x == who:
            problems.append(f"{who}: related names the entry itself")
    if len(set(rel)) != len(rel):
        problems.append(f"{who}: `related` repeats an id")


def check_related(*registers: list[dict]) -> None:
    """Every ``related:`` id is a live entry of one of ``registers`` (validated lists)."""
    live = {str(e.get("id")) for reg in registers for e in reg}
    problems = [
        f"{e['id']}: related {x} is not a live lesson or runbook"
        for reg in registers
        for e in reg
        for x in e.get("related") or ()
        if x not in live
    ]
    if problems:
        raise RegisterError("related", problems)


def _retired(data, live, id_rx: re.Pattern, problems: list[str]) -> dict:
    """The optional top-level ``retired:`` mapping of tombstoned ids (see registers.ids).

    {ID: {reason: why it was retired, replaced_by: live ID or omitted}}.  A tombstone may not
    name a live id (that is reuse) and may only point at an id that is live.
    """
    ret = data.get("retired") if isinstance(data, dict) else None
    if ret is None:
        return {}
    if not isinstance(ret, dict):
        problems.append("`retired` must be a mapping of id -> {reason, replaced_by}")
        return {}
    live = {i for i in live if not i.endswith("-NEW")}
    for k, v in ret.items():
        who = f"retired {k}"
        if not id_rx.match(str(k)) or str(k).endswith("-NEW"):
            problems.append(f"{who}: only an allocated id can be retired")
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


def validate_lessons(data) -> list[dict]:
    items = _entries(data, "lessons", "lessons")
    problems: list[str] = []
    allowed = {
        "id",
        "title",
        "date",
        "systems",
        "recurrences",
        "status",
        "symptom",
        "contributing_factor",
        "root_cause",
        "preventive_control",
        "verification",
        "open_reason",
        "notes",
        "related",
    }
    _dupes([str(e.get("id")) for e in items if isinstance(e, dict)], problems)
    _retired(data, [str(e.get("id")) for e in items if isinstance(e, dict)], LESSON_ID, problems)
    for e in items:
        if not isinstance(e, dict):
            problems.append(f"entry is not a mapping: {e!r}")
            continue
        who = str(e.get("id", "<no id>"))
        if not LESSON_ID.match(who):
            problems.append(
                f"{who}: id must look like LL-123 (use LL-NEW and let register_ids allocate)"
            )
        extra = set(e) - allowed
        if extra:
            problems.append(f"{who}: unknown field(s) {sorted(extra)}")
        _text(e, "title", problems, who, 4)
        _related(e, who, problems)
        if not _date(e.get("date")):
            problems.append(f"{who}: `date` must be ISO YYYY-MM-DD")
        s = e.get("systems")
        if not (isinstance(s, list) and s and all(isinstance(x, str) and x for x in s)):
            problems.append(f"{who}: `systems` must be a non-empty list of strings")
        r = e.get("recurrences")
        if not (isinstance(r, int) and not isinstance(r, bool) and r >= 0):
            problems.append(f"{who}: `recurrences` must be an integer >= 0")
        status = e.get("status")
        if status not in LESSON_STATUSES:
            problems.append(f"{who}: `status` must be one of {LESSON_STATUSES}")
        _text(e, "symptom", problems, who)
        _text(e, "contributing_factor", problems, who)
        rc = _text(e, "root_cause", problems, who)
        if rc and (w := _weak(rc)):
            problems.append(f"{who}: root_cause is a person/behaviour ({w!r}); go one level deeper")
        pc = e.get("preventive_control")
        if pc is None and status == "open":
            if (
                not isinstance(e.get("open_reason"), str)
                or len(e["open_reason"].strip()) < MIN_TEXT
            ):
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
            obs = _text(v, "observable", problems, f"{who}.verification", 6)
            exp = _text(v, "expected", problems, f"{who}.verification", 3)
            for txt in (obs, exp):
                if txt and any(u in txt.lower() for u in UNFALSIFIABLE):
                    problems.append(f"{who}: verification is not falsifiable ({txt!r})")
        if status == "controlled" and isinstance(v, dict) and not e.get("preventive_control"):
            problems.append(f"{who}: controlled needs a preventive_control")
    if problems:
        raise RegisterError("lessons", problems)
    return items


def validate_runbooks(data) -> list[dict]:
    items = _entries(data, "runbooks", "runbooks")
    problems: list[str] = []
    _dupes([str(e.get("id")) for e in items if isinstance(e, dict)], problems)
    _retired(data, [str(e.get("id")) for e in items if isinstance(e, dict)], RUNBOOK_ID, problems)
    for e in items:
        if not isinstance(e, dict):
            problems.append(f"entry is not a mapping: {e!r}")
            continue
        who = str(e.get("id", "<no id>"))
        if not RUNBOOK_ID.match(who):
            problems.append(f"{who}: id must look like RB-123")
        _text(e, "title", problems, who, 4)
        _related(e, who, problems)
        _text(e, "purpose", problems, who)
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
    if problems:
        raise RegisterError("runbooks", problems)
    return items


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
