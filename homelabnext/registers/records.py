# SPDX-License-Identifier: Apache-2.0
"""One record per file: lessons and runbooks as Markdown with YAML front-matter.

A register is either a legacy single YAML file (``lessons.yml``) or a directory of record files
(``lessons/LL-001.md``).  :func:`load_register` reads either and returns the document the
validators take (``{"lessons": [...], "retired": {...}}``), so validation is the same code on the
same dicts whichever form is on disk.

A record file::

    ---
    id: LL-001                      # the key; the file is named <id>.md (LL-NEW-<slug>.md
    title: ...                      # until a maintainer allocates the number)
    kind: pitfall                   # pitfall | practice, each with its lifecycle (schema.py)
    status: controlled
    date: 2026-01-12
    author: unknown                 # reviews: see homelabnext.reviews
    systems: [proxy, tls]
    recurrences: 1
    review_by: 2027-01-17
    verification: {observable: ..., expected: ...}
    related: [RB-001]               # optional typed links to other lessons/runbooks
    reviews: [...]
    ---

    ## Symptom
    ...prose...

    ## Root cause
    ...

    ## Links
    <!-- hnx:gen:links -->
    - Systems: [[systems/proxy|proxy]], [[systems/tls|tls]]
    - Related: [[RB-001]]
    <!-- /hnx:gen -->

Short structured fields live in the front-matter (Obsidian shows them as properties); the long
prose fields are named ``## Heading`` sections of the body, one heading per field, so they are
edited as ordinary Markdown.  A runbook's ``steps`` are the ``## Steps`` section, a numbered
list where every item carries its own ``- verify:`` line.  The parser maps each section back to
its field (surrounding whitespace is not significant, so YAML folding's trailing newline is
dropped from both forms), refuses an unknown heading, a duplicate heading, a prose field in the
front-matter, text outside a section and a file name that disagrees with its id.

The ``## Links`` section is generated from the record's own front-matter only (``systems``,
``related``, a tombstone's ``replaced_by``), so editing one record never makes another stale and
the per-file layout keeps its point: two authors never touch the same file.  ``hnx registers
links DIR`` rewrites it and ``--check`` fails when one is stale; the loader ignores it.

A retired id is a record file whose front-matter is ``id:`` plus a ``retired:`` mapping
(``reason``, optional ``replaced_by``), the per-file form of the YAML ``retired:`` block.

What several writers append to (reviews, recurrences, verification stamps, applied lifecycle
transitions) lives beside the record in ``<id>.events/``, one file per event
(:mod:`homelabnext.registers.events`); the loader derives ``reviews``, ``recurrences``,
``last_verified`` and the current status from them, so the document keeps its shape.  Inline
``reviews:`` / ``recurrences:`` still load (the base the events add to); ``hnx registers events
migrate`` moves them out.
"""

from __future__ import annotations

import pathlib
import re
from collections.abc import Mapping

import yaml

from . import events as ev
from . import ids
from .schema import RegisterError, is_active, record_digest_of

__all__ = [
    "RECORD_KINDS",
    "SECTIONS",
    "join_register",
    "load_register",
    "load_texts",
    "parse_record",
    "record_digest",
    "record_name",
    "refresh_links",
    "register_source",
    "render_record",
    "split_register",
    "stale_links",
]

RECORD_KINDS = ("lessons", "runbooks")
# field -> body heading, in the order a record file writes them
SECTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "lessons": (
        ("symptom", "Symptom"),
        ("contributing_factor", "Contributing factor"),
        ("root_cause", "Root cause"),
        ("preventive_control", "Preventive control"),
        ("open_reason", "Open reason"),
        ("method", "Method"),
        ("rationale", "Rationale"),
        ("retired_reason", "Retired reason"),
        ("notes", "Notes"),
    ),
    "runbooks": (("purpose", "Purpose"), ("steps", "Steps")),
    # the strategy-to-task records (homelabnext.strategy): parsed and linked by the same code
    "strategy": (
        ("mission", "Mission"),
        ("intent", "Intent"),
        ("end_state", "End state"),
        ("notes", "Notes"),
    ),
    "objectives": (("statement", "Statement"), ("notes", "Notes")),
    "measures": (
        ("definition", "Definition"),
        ("not_measurable", "Not measurable"),
        ("notes", "Notes"),
    ),
    "requirements": (
        ("question", "Question"),
        ("decision_supported", "Decision supported"),
        ("acceptance", "Acceptance"),
        ("guardrails", "Guardrails"),
        ("notes", "Notes"),
    ),
    "rfis": (("question", "Question"), ("answer", "Answer"), ("notes", "Notes")),
}
FRONT_ORDER = {
    "lessons": (
        *("id", "title", "kind", "status", "date", "author", "systems", "applies_to"),
        *("recurrences", "review_by", "retired_on", "retired_by", "incorporated_into"),
        *("superseded_by", "verification", "related", "reviews"),
    ),
    "runbooks": (
        "id",
        "title",
        "systems",
        "last_reviewed",
        "review_by",
        "superseded_by",
        "related",
    ),
    "rfis": (
        *("id", "title", "status", "date", "author", "raised_by", "triage", "ltiov"),
        *("tasked_to", "intent"),
    ),
}
# typed links of the strategy records, shown in their Links block: field -> label
LINK_FIELDS = (
    ("parent", "Parent"),
    ("objective", "Objective"),
    ("measures", "Measured by"),
    ("supports", "Supports"),
    ("serves", "Serves"),
    ("raised_by", "Raised by"),
)
LINKS = "Links"
GEN_OPEN, GEN_CLOSE = "<!-- hnx:gen:links -->", "<!-- /hnx:gen -->"

_FRONT = re.compile(r"\A---\n(?P<fm>.*?)\n?^---[ \t]*(?:\n|\Z)", re.S | re.M)
_H2 = re.compile(r"^##[ \t]+(?P<h>.+?)[ \t]*$")
_FENCE = re.compile(r"^ {0,3}(?P<f>`{3,}|~{3,})")
_STEP = re.compile(r"^(?P<n>\d+)\.(?:[ \t]+(?P<t>.*))?$")
_VERIFY = re.compile(r"^[ \t]+[-*][ \t]+verify:(?:[ \t]*(?P<t>.*))?$")
_FROM = re.compile(r"^[ \t]+[-*][ \t]+from_lessons:(?:[ \t]*(?P<t>.*))?$")
_FROM_ID = re.compile(r"^(?:\[\[(?P<w>[^\]|]+)\]\]|(?P<p>[^\s,\[\]]+))$")


# --- parsing ---------------------------------------------------------------------------------


def _headings(lines: list[str]):
    """Yield (index, heading or None) per line: a ``## `` heading outside fenced code."""
    fence = None
    for i, ln in enumerate(lines):
        f = _FENCE.match(ln)
        if f:
            tok = f.group("f")
            if fence is None:
                fence = tok
            elif tok[0] == fence[0] and len(tok) >= len(fence):
                fence = None
            yield i, None
            continue
        h = None if fence else _H2.match(ln)
        yield i, (h.group("h") if h else None)


def _split_body(body: str, name: str, problems: list[str]) -> list[tuple[str, int, str]]:
    """[(heading, line number, text)] of the body's ``## `` sections (fenced code is opaque)."""
    sections: list[tuple[str, int, list[str]]] = []
    pre: list[str] = []
    lines = body.split("\n")
    for i, h in _headings(lines):
        ln = lines[i]
        if h:
            sections.append((h, i + 1, []))
        elif sections:
            sections[-1][2].append(ln)
        else:
            pre.append(ln)
    if "".join(pre).strip():
        problems.append(f"{name}: text before the first `## ` section (every line belongs to one)")
    return [(h, n, "\n".join(lines).strip()) for h, n, lines in sections]


def _steps(text: str, name: str, problems: list[str]) -> list[dict]:
    steps: list[dict] = []
    for n, ln in enumerate(text.split("\n"), 1):
        if not ln.strip():
            continue
        if m := _STEP.match(ln):
            steps.append({"do": (m.group("t") or "").strip()})
        elif (m := _VERIFY.match(ln)) and steps and "verify" not in steps[-1]:
            steps[-1]["verify"] = (m.group("t") or "").strip()
        elif (m := _FROM.match(ln)) and steps and "from_lessons" not in steps[-1]:
            refs = [r.strip() for r in (m.group("t") or "").split(",") if r.strip()]
            got = [_FROM_ID.match(r) for r in refs]
            if not refs or not all(got):
                problems.append(f"{name}: `## Steps` line {n}: from_lessons wants [[LL-001]], ...")
            steps[-1]["from_lessons"] = [g.group("w") or g.group("p") for g in got if g]
        else:
            problems.append(
                f"{name}: `## Steps` line {n} is not `N. <do>`, or an indented `- verify: <check>`"
                " or `- from_lessons: [[LL-001]]` under a step without one"
            )
    return steps


def parse_record(text: str, name: str, kind: str, problems: list[str]) -> dict | None:
    """One record file -> its entry dict, or ``{"id": ..., "retired": {...}}`` for a tombstone.

    Problems are appended (all of them, so an author fixes a file in one pass); None when the
    file cannot be read as a record at all.
    """
    text = text.replace("\r\n", "\n")
    m = _FRONT.match(text)
    if not m:
        problems.append(f"{name}: must start with a `---` YAML front-matter block")
        return None
    try:
        fm = yaml.safe_load(m.group("fm")) if m.group("fm").strip() else None
    except yaml.YAMLError as ex:
        problems.append(f"{name}: front-matter is not YAML ({ex})".replace("\n", " "))
        return None
    if not isinstance(fm, dict):
        problems.append(f"{name}: front-matter must be a mapping")
        return None
    spec = ids.SPECS.get(kind)  # None: a single record that is not an id register (strategy)
    ident = fm.get("id")
    bad = spec and ids.record_name_problem(
        name,
        str(ident) if ident is not None and re.fullmatch(spec.id_re, str(ident)) else None,
        spec,
    )
    if bad:
        problems.append(bad)
    fields = dict(SECTIONS[kind])
    headings = {h: f for f, h in SECTIONS[kind]}
    for k in fm:
        if k in fields:
            problems.append(f"{name}: `{k}` belongs in the body as a `## {fields[k]}` section")
    entry = dict(fm)
    seen: set[str] = set()
    for heading, line, body in _split_body(text[m.end() :], name, problems):
        if heading in seen:
            problems.append(f"{name}: `## {heading}` appears twice")
            continue
        seen.add(heading)
        if heading == LINKS:
            continue  # generated from the front-matter; refresh_links owns it
        field = headings.get(heading)
        if field is None:
            allowed = ", ".join(f"`## {h}`" for h in [*headings, LINKS])
            problems.append(f"{name}: line {line}: unknown section `## {heading}` ({allowed})")
            continue
        if not body:
            continue  # an empty section is an absent field (the schema says if it is required)
        entry[field] = _steps(body, name, problems) if field == "steps" else body
    if "retired" in fm:
        extra = set(entry) - {"id", "retired"}
        if extra:
            problems.append(
                f"{name}: a tombstone holds only `id` and `retired`, not {sorted(extra)}"
            )
    return entry


def record_digest(text: str, name: str, kind: str, events=()) -> str:
    """The digest a review of this record file must carry (``hnx reviews digest FILE``): the
    record as loaded (its ``events`` applied) without its reviews, so the Links block, formatting
    and verification stamps do not count."""
    problems: list[str] = []
    entry = parse_record(text, name, kind, problems)
    if entry is not None and not problems:
        entry = ev.derive(entry, events, kind, problems, name)
    if problems or entry is None:
        raise RegisterError(kind, problems or [f"{name}: not a record"])
    return record_digest_of(_canonical({kind: [entry]}, kind)[kind][0])


def load_texts(
    texts: Mapping[str, str], kind: str, events: Mapping[str, list[ev.Event]] | None = None
) -> dict:
    """Record file texts ``{file name: text}`` (and each file's sidecar events, by record file
    name) -> the register document with derived fields filled in (fatal on any problem)."""
    if kind not in SECTIONS:
        raise RegisterError(kind, [f"record directories hold {' or '.join(SECTIONS)} only"])
    problems: list[str] = []
    events = events or {}
    for name in sorted(set(events) - set(texts)):
        stem = name[: -len(ids.RECORD_SUFFIX)]
        problems.append(f"{stem}{ev.EVENTS_SUFFIX}: no record file {name} beside it")
    entries, retired = [], {}
    for name in sorted(texts):
        rec = parse_record(texts[name], name, kind, problems)
        if rec is None:
            continue
        if "retired" in rec:
            if events.get(name):
                problems.append(f"{name}: a tombstone has no events")
            retired[str(rec.get("id"))] = rec["retired"]
        else:
            entries.append(ev.derive(rec, events.get(name, ()), kind, problems, name))
    if problems:
        raise RegisterError(kind, problems)
    doc: dict = {kind: entries}
    if retired:
        doc["retired"] = retired
    return doc


def _canonical(doc, kind: str):
    """Prose fields without surrounding whitespace (YAML folding adds a trailing newline that no
    reader uses; a Markdown section cannot carry one), so both forms load to equal dicts."""
    if kind not in SECTIONS or not isinstance(doc, dict) or not isinstance(doc.get(kind), list):
        return doc
    prose = [f for f, _ in SECTIONS[kind] if f != "steps"]
    for e in doc[kind]:
        if not isinstance(e, dict):
            continue
        for f in prose:
            if isinstance(e.get(f), str):
                e[f] = e[f].strip()
        steps = e.get("steps") if kind == "runbooks" else None
        for st in steps if isinstance(steps, list) else ():
            if isinstance(st, dict):
                for k in ("do", "verify"):  # from_lessons ids are not prose
                    if isinstance(st.get(k), str):
                        st[k] = st[k].strip()
    return doc


def _kind_of(path: pathlib.Path) -> str:
    return path.stem.split(".")[0] if path.suffix else path.name


def load_register(path, kind: str | None = None, *, active_only: bool = False) -> dict:
    """The one reader of a register: a record directory or a single YAML file -> its document.

    ``kind`` defaults to the directory name or the file stem (``lessons``, ``runbooks``,
    ``invariants``, ``queue``).  Lessons and runbooks come back with prose fields stripped of
    surrounding whitespace in both forms; any other register is the YAML as parsed.
    ``active_only`` drops retired, incorporated and superseded lessons and superseded runbooks
    (:func:`homelabnext.registers.schema.is_active`): what a graph or a context pack should read.
    It filters, it does not validate; validate the full document (references into the archive
    must resolve).
    """
    doc = _load(pathlib.Path(path), kind)
    kind = kind or _kind_of(pathlib.Path(path))
    if active_only and kind in RECORD_KINDS:
        entries = [e for e in doc[kind] if not isinstance(e, dict) or is_active(e, kind)]
        doc = {**doc, kind: entries}
    return doc


def _load(p: pathlib.Path, kind: str | None) -> dict:
    kind = kind or _kind_of(p)
    if p.is_dir():
        texts, problems = read_dir(p)
        events = dir_events(p, problems)
        if problems:
            raise RegisterError(kind, problems)
        return load_texts(texts, kind, events)
    if p.is_file():
        return _canonical(yaml.safe_load(p.read_text()), kind)
    raise RegisterError(kind, [f"{p}: no such register file or directory"])


def read_dir(p: pathlib.Path) -> tuple[dict[str, str], list[str]]:
    """``{name: text}`` of a record directory's record files, and what else is in it that
    should not be (``<stem>.events/`` sidecar directories belong)."""
    texts, problems = {}, []
    for f in sorted(p.iterdir()):
        if f.name.startswith(".") or ev.is_events_dir(f):
            continue
        if not f.is_file() or f.suffix != ids.RECORD_SUFFIX:
            problems.append(
                f"{f.name}: not a record file (a record directory holds *.md and their"
                f" <stem>{ev.EVENTS_SUFFIX}/ directories only)"
            )
            continue
        texts[f.name] = f.read_text()
    return texts, problems


def dir_events(p: pathlib.Path, problems: list[str]) -> dict[str, list[ev.Event]]:
    """Every sidecar ``<stem>.events/`` of a record directory, keyed by record file name."""
    out = {}
    for f in sorted(p.iterdir()):
        if ev.is_events_dir(f):
            name = f.name[: -len(ev.EVENTS_SUFFIX)] + ids.RECORD_SUFFIX
            out[name] = ev.read_events(f, problems, name)
    return out


def register_source(src_dir, kind: str) -> pathlib.Path | None:
    """``SRC/<kind>/`` or ``SRC/<kind>.yml``; both at once is ambiguous and fatal."""
    src = pathlib.Path(src_dir)
    found = [p for p in (src / kind, src / f"{kind}.yml") if p.exists()]
    if len(found) > 1:
        raise RegisterError(
            kind, [f"both {found[0]} and {found[1]} exist; keep one (`hnx registers split|join`)"]
        )
    return found[0] if found else None


# --- writing ---------------------------------------------------------------------------------


def _scalar_list(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, (str, int, float)) for x in v)


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):  # a repeated date is written twice, never as &id001
        return True


def _dump_front(entry: Mapping, kind: str) -> str:
    keys = [k for k in FRONT_ORDER.get(kind, ()) if k in entry]
    keys += [k for k in entry if k not in keys and k not in dict(SECTIONS[kind])]
    out = []
    for k in keys:
        v = entry[k]
        if _scalar_list(v):
            flow = yaml.safe_dump(v, default_flow_style=True, width=1 << 16, allow_unicode=True)
            out.append(f"{k}: {flow.strip()}")
        else:
            out.append(
                yaml.dump(
                    {k: v}, Dumper=_Dumper, sort_keys=False, width=1 << 16, allow_unicode=True
                ).rstrip("\n")
            )
    return "\n".join(out)


def _wiki(ident: str) -> str:
    return f"[[{ident}]]"


def _destination(ref: str) -> str:
    path, _, anchor = ref.partition("#")
    if path.startswith("docs/systems/"):  # the docs/ vault's own path-qualified form
        stem = path[len("docs/systems/") : -len(".md")]
        return f"[[systems/{stem}|{stem}]]" + (f" ({anchor})" if anchor else "")
    return _wiki(path) + (f" step {anchor}" if anchor else "")


def _archive_row(entry: Mapping) -> str | None:
    """``- Archive: ...`` for an inactive record, so every reader can see it is history."""
    status = entry.get("status")
    if entry.get("superseded_by"):
        return f"- Archive: superseded by {_wiki(str(entry['superseded_by']))}"
    if status == "incorporated" and _scalar_list(entry.get("incorporated_into")):
        dest = ", ".join(_destination(str(r)) for r in entry["incorporated_into"])
        return f"- Archive: incorporated into {dest}"
    if status == "retired":
        by = entry.get("retired_by")
        how = f" by {', '.join(f'`{r}`' for r in by)}" if _scalar_list(by) and by else ""
        on = f" on {entry['retired_on']}" if entry.get("retired_on") else ""
        return f"- Archive: retired{on}{how}"
    return None


def links_block(entry: Mapping) -> str:
    """The generated ``## Links`` section: wiki-links for this record's typed links only."""
    rows = []
    if isinstance(entry.get("retired"), dict):
        rb = entry["retired"].get("replaced_by")
        rows.append("- Retired" + (f"; replaced by {_wiki(str(rb))}" if rb else ""))
    if archive := _archive_row(entry):
        rows.append(archive)
    applies = entry.get("applies_to")
    if _scalar_list(applies) and applies:
        rows.append("- Applies to: " + ", ".join(f"`{a}`" for a in applies))
    systems = entry.get("systems")
    if _scalar_list(systems) and systems:
        rows.append("- Systems: " + ", ".join(f"[[systems/{s}|{s}]]" for s in systems))
    related = entry.get("related")
    if _scalar_list(related) and related:
        rows.append("- Related: " + ", ".join(_wiki(str(r)) for r in related))
    for field, label in LINK_FIELDS:
        v = entry.get(field)
        refs = [v] if isinstance(v, str) else v if _scalar_list(v) else []
        if refs:
            rows.append(f"- {label}: " + ", ".join(_wiki(str(r)) for r in refs))
    body = "\n".join(rows or ["- none"])
    return f"## {LINKS}\n\n{GEN_OPEN}\n{body}\n{GEN_CLOSE}\n"


def _render_step(n: int, st: Mapping) -> str:
    out = f"{n}. {st.get('do', '')}"
    if "verify" in st:
        out += f"\n   - verify: {st['verify']}"
    if "from_lessons" in st:  # wiki-links in the body: the graph sees SOP -> lesson provenance
        out += "\n   - from_lessons: " + ", ".join(_wiki(str(i)) for i in st["from_lessons"])
    return out


def render_record(entry: Mapping, kind: str) -> str:
    """The canonical record file for one entry (or ``{"id", "retired"}`` tombstone)."""
    parts = [f"---\n{_dump_front(entry, kind)}\n---\n"]
    if "retired" not in entry:
        for field, heading in SECTIONS[kind]:
            if field not in entry:
                continue
            v = entry[field]
            if field == "steps":
                v = "\n".join(_render_step(n, st) for n, st in enumerate(v, 1))
            parts.append(f"## {heading}\n\n{v}\n")
    parts.append(links_block(entry))
    return "\n".join(parts)


def record_name(entry: Mapping, kind: str, taken: set[str]) -> str:
    """``<id>.md``; a placeholder gets ``LL-NEW-<slug of its title>.md``, unique in ``taken``."""
    ident = str(entry.get("id"))
    if not ident.endswith("-NEW"):
        return f"{ident}{ids.RECORD_SUFFIX}"
    slug = re.sub(r"[^a-z0-9]+", "-", str(entry.get("title", "")).lower()).strip("-")[:48]
    slug = slug.strip("-") or "record"
    name, n = f"{ident}-{slug}{ids.RECORD_SUFFIX}", 2
    while name in taken:
        name, n = f"{ident}-{slug}-{n}{ids.RECORD_SUFFIX}", n + 1
    return name


def _diff(a, b, path="") -> str:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                return f"{path}{k} is {'added' if k not in a else 'dropped'}"
            if d := _diff(a[k], b[k], f"{path}{k}."):
                return d
        return ""
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return next(
            (
                d
                for i, (x, y) in enumerate(zip(a, b, strict=True))
                if (d := _diff(x, y, f"{path}{i}."))
            ),
            "",
        )
    return "" if a == b and type(a) is type(b) else f"{path.rstrip('.')}: {a!r} != {b!r}"


def _unordered(doc: dict, kind: str) -> dict:
    return {**doc, kind: sorted(doc[kind], key=lambda e: repr(sorted(e.items(), key=str)))}


def split_register(src, out_dir) -> list[pathlib.Path]:
    """Convert a single-file register into a record directory, losslessly or not at all.

    The register must validate first.  Each entry's inline reviews and recurrences become sidecar
    events (:func:`homelabnext.registers.events.backfill`); every rendered file is parsed back,
    its events applied, and compared with its entry, and nothing is written unless all of them
    round-trip exactly.  The files are written by
    :func:`homelabnext.registers.write.write_register`.
    """
    from .schema import validate_lessons, validate_runbooks
    from .write import write_register

    src, out = pathlib.Path(src), pathlib.Path(out_dir)
    kind = _kind_of(src)
    if kind not in RECORD_KINDS:
        raise RegisterError(kind, [f"{src}: only {' and '.join(RECORD_KINDS)} split into records"])
    if out.exists() and any(out.iterdir()):
        raise RegisterError(kind, [f"{out} exists and is not empty"])
    doc = load_register(src, kind)
    {"lessons": validate_lessons, "runbooks": validate_runbooks}[kind](doc)
    records = [dict(e) for e in doc[kind]]
    records += [{"id": i, "retired": t} for i, t in (doc.get("retired") or {}).items()]
    files, texts, events, problems = {}, {}, {}, []
    for e in records:
        name = record_name(e, kind, set(files))
        rest, evs = (e, []) if "retired" in e else ev.backfill(e, kind)
        text = render_record(rest, kind)
        pending = [ev.Event(ev.event_name(x, w), x, ev.stamp_of(w), 1) for x, w in evs]
        back = parse_record(text, name, kind, problems)
        if back is not None and "retired" not in back:
            back = ev.derive(back, pending, kind, problems, name)
        if back is not None and (d := _diff(e, back)):
            problems.append(f"{e.get('id')}: does not survive the round trip ({d})")
        files[name], texts[name], events[name] = (rest, evs), text, pending
    if problems:
        raise RegisterError(kind, problems)
    back_doc = load_texts(texts, kind, events)
    if _unordered(back_doc, kind) != _unordered(doc, kind):  # files load in name order
        raise RegisterError(kind, ["the record directory does not load back to the register"])
    return write_register(out, files, check_refs=False, policy=False)


def join_register(src_dir, out_file) -> pathlib.Path:
    """The reverse of :func:`split_register`: one YAML file, for review or a downstream tool.
    The sidecar events are folded in: the file carries the derived ``reviews`` and
    ``recurrences`` inline (a single file has no sidecars)."""
    src, out = pathlib.Path(src_dir), pathlib.Path(out_file)
    kind = _kind_of(src)
    doc = load_register(src, kind)
    entries = []
    for e in doc[kind]:
        keys = [k for k in FRONT_ORDER[kind] if k in e]
        keys += [f for f, _ in SECTIONS[kind] if f in e]
        keys += [k for k in e if k not in keys]
        entries.append({k: e[k] for k in keys})
    body = {kind: entries, **({"retired": doc["retired"]} if doc.get("retired") else {})}
    text = "# SPDX-License-Identifier: Apache-2.0\n" + yaml.safe_dump(
        body, sort_keys=False, width=100, allow_unicode=True
    )
    if _canonical(yaml.safe_load(text), kind) != doc:
        raise RegisterError(kind, [f"{out}: the joined file would not load back to {src}"])
    from homelabnext.state import atomic_write_text

    return atomic_write_text(out, text, mode=ev.FILE_MODE)


# --- the generated links block -----------------------------------------------------------------


def refresh_links(text: str, kind: str) -> str:
    """``text`` with its ``## Links`` section regenerated from its own front-matter (appended
    when missing).  A file that is not a parseable record is returned unchanged."""
    norm = text.replace("\r\n", "\n")
    m = _FRONT.match(norm)
    if not m:
        return text
    try:
        fm = yaml.safe_load(m.group("fm"))
    except yaml.YAMLError:
        return text
    if not isinstance(fm, dict):
        return text
    block = links_block(fm)
    front, lines = norm[: m.end()], norm[m.end() :].split("\n")
    start = end = None
    for i, h in _headings(lines):
        if h and start is None and h == LINKS:
            start = i
        elif h and start is not None:
            end = i
            break
    if start is None:
        return norm.rstrip("\n") + "\n\n" + block
    before = "\n".join(lines[:start]).rstrip("\n")
    tail = "\n".join(lines[end:]).rstrip("\n") if end is not None else ""
    return (
        front
        + (before + "\n\n" if before.strip() else "\n")
        + block
        + ("\n" + tail + "\n" if tail else "")
    )


def stale_links(dir_path, write: bool = False) -> list[pathlib.Path]:
    """Record files whose ``## Links`` block is not what the front-matter generates (rewritten
    when ``write``)."""
    d = pathlib.Path(dir_path)
    kind = _kind_of(d)
    stale = []
    for p in sorted(d.glob(f"*{ids.RECORD_SUFFIX}")):
        text = p.read_text()
        fresh = refresh_links(text, kind)
        if fresh != text:
            stale.append(p)
            if write:
                p.write_text(fresh)
    return stale
