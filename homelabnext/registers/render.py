# SPDX-License-Identifier: Apache-2.0
"""Static HTML + JSON generators. No external assets, no scripts, no timestamps of their own
(output is a pure function of the inputs, so a regenerate with no change produces no diff).
"""

from __future__ import annotations

import html
import json
import pathlib

import yaml

from .records import load_register, register_source
from .schema import (
    RegisterError,
    check_links,
    is_active,
    validate_invariants,
    validate_lessons,
    validate_runbooks,
)

__all__ = ["build_all", "load_yaml", "render_invariants", "render_lessons", "render_runbooks"]

CSS = """
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d0d7de;--card:#f6f8fa;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--card:#161b22;--ok:#3fb950;--bad:#f85149;--warn:#d29922}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:60rem;padding:1rem 16px}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid var(--line)}
article{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.6rem 1rem;margin:.8rem 0}
dt{color:var(--mut);font-size:.8rem;text-transform:uppercase;margin-top:.5rem}dd{margin:0}
code,pre{font-family:ui-monospace,monospace;font-size:.85rem;white-space:pre-wrap;overflow-wrap:anywhere}
.pass,.controlled{color:var(--ok)}.fail,.error,.open{color:var(--bad)}.partial,.skip,.untested{color:var(--warn)}
.pill{border:1px solid currentColor;border-radius:1rem;padding:0 .5rem;font-size:.75rem}
"""


def load_yaml(path):
    return yaml.safe_load(pathlib.Path(path).read_text())


def e(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def page(title: str, body: str, summary: str) -> str:
    return (
        f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{e(title)}</title><style>{CSS}</style></head><body>"
        f"<h1>{e(title)}</h1><p>{e(summary)}</p>{body}</body></html>\n"
    )


def _dl(rows) -> str:
    return "<dl>" + "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in rows if v) + "</dl>"


def _related_html(ids) -> str:
    """``related:`` ids as links into the lessons or runbooks page."""
    return ", ".join(
        f'<a href="{"lessons" if i.startswith("LL-") else "runbooks"}.html#{e(i)}">{e(i)}</a>'
        for i in ids or ()
    )


def _p(x) -> str:
    return "".join(f"<p>{e(par)}</p>" for par in str(x or "").strip().split("\n\n") if par.strip())


def _review_html(r: dict) -> str:
    from homelabnext.reviews import evaluate

    from .schema import record_digest_of

    ev = evaluate(
        r.get("reviews"), author=r.get("author"), digest=record_digest_of(r), artefact="", state=""
    )
    rows = [
        f"{e(x['date'])} {e(x['by'])} ({e(x['kind'])} {e(x['role'])}): {e(x['verdict'])}"
        for x in ev.current
    ]
    stale = f" ({len(ev.stale)} of an earlier version)" if ev.stale else ""
    return "<br>".join(rows) + e(stale) if rows or stale else ""


def _archive(cards: list[str], archived: list[str]) -> str:
    """Active records first; graduated or replaced ones under an Archive heading."""
    if not archived:
        return "".join(cards)
    return (
        "".join(cards)
        + "<h2>Archive</h2><p>Retired, incorporated and superseded records: kept because their "
        "ids are cited, skipped by the graph and context packs.</p>" + "".join(archived)
    )


def _lesson_card(l: dict) -> str:
    v = l.get("verification") or {}
    if l["kind"] == "practice":
        rows = [
            ("Applies to", e(", ".join(l["applies_to"]))),
            ("Method", _p(l["method"])),
            ("Rationale", _p(l.get("rationale"))),
            ("Incorporated into", e(", ".join(l.get("incorporated_into") or ()))),
            (
                "Superseded by",
                _related_html([l["superseded_by"]] if l.get("superseded_by") else []),
            ),
            ("Retired", _p(l.get("retired_reason"))),
        ]
    else:
        rows = [
            ("Recurrences", e(l["recurrences"])),
            ("Symptom", _p(l["symptom"])),
            ("Contributing factor", _p(l["contributing_factor"])),
            ("Root cause", _p(l["root_cause"])),
            ("Preventive control", _p(l.get("preventive_control")) or _p(l.get("open_reason"))),
            (
                "Retired by",
                e(", ".join(l.get("retired_by") or ())) if l["status"] == "retired" else "",
            ),
        ]
    return (
        f'<article id="{e(l["id"])}"><h3>{e(l["id"])} {e(l["title"])} '
        f'<span class="pill">{e(l["kind"])}</span> '
        f'<span class="pill {e(l["status"])}">{e(l["status"])}</span></h3>'
        + _dl(
            [
                ("Date", e(l["date"])),
                ("Systems", e(", ".join(l["systems"]))),
                *rows,
                ("Verification: observable", f"<code>{e(v.get('observable'))}</code>" if v else ""),
                ("Verification: expected", e(v.get("expected")) if v else ""),
                ("Review by", e(l.get("review_by"))),
                ("Reviews", _review_html(l)),
                ("Related", _related_html(l.get("related"))),
            ]
        )
        + "</article>"
    )


def render_lessons(data, policy=None) -> tuple[str, dict]:
    items = validate_lessons(data, policy)
    ordered = sorted(items, key=lambda x: x["id"])
    cards = [_lesson_card(l) for l in ordered if is_active(l)]
    archived = [_lesson_card(l) for l in ordered if not is_active(l)]
    counts: dict[str, int] = {}
    for l in items:
        counts[l["status"]] = counts.get(l["status"], 0) + 1
    by_kind = {k: sum(1 for l in items if l["kind"] == k) for k in ("pitfall", "practice")}
    doc = {
        "register": "lessons",
        "count": len(items),
        "active": len(cards),
        "by_kind": by_kind,
        "by_status": dict(sorted(counts.items())),
        "lessons": ordered,
    }
    summary = f"{len(items)} lessons ({len(cards)} active, {len(archived)} archived): " + ", ".join(
        f"{n} {s}" for s, n in sorted(counts.items())
    )
    return page("Lessons", _archive(cards, archived), summary), json.loads(
        json.dumps(doc, default=str)
    )


def render_runbooks(data, lessons=None, policy=None) -> tuple[str, dict]:
    items = validate_runbooks(data, policy)
    lessons = [l for l in lessons or [] if is_active(l)]
    cards, archived, out = [], [], []
    for r in sorted(items, key=lambda x: x["id"]):
        rel = [l for l in lessons if set(l["systems"]) & set(r["systems"])]
        steps = "".join(
            f"<li>{e(s['do'])}<br><small>verify: <code>{e(s['verify'])}</code></small>"
            + (
                f"<br><small>from {_related_html(s['from_lessons'])}</small>"
                if s.get("from_lessons")
                else ""
            )
            + "</li>"
            for s in r["steps"]
        )
        lessons_html = "".join(
            f'<li><a href="lessons.html#{e(l["id"])}">{e(l["id"])}</a> {e(l["title"])}</li>'
            for l in sorted(rel, key=lambda x: x["id"])
        )
        card = (
            f'<article id="{e(r["id"])}"><h3>{e(r["id"])} {e(r["title"])}</h3>'
            + _dl(
                [
                    ("Purpose", _p(r["purpose"])),
                    ("Systems", e(", ".join(r["systems"]))),
                    ("Checklist", f"<ol>{steps}</ol>"),
                    ("Lessons sharing these systems", f"<ul>{lessons_html}</ul>" if rel else ""),
                    (
                        "Superseded by",
                        _related_html([r["superseded_by"]] if r.get("superseded_by") else []),
                    ),
                    ("Review by", e(r.get("review_by"))),
                    ("Reviews", _review_html(r)),
                    ("Related", _related_html(r.get("related"))),
                ]
            )
            + "</article>"
        )
        (cards if is_active(r, "runbooks") else archived).append(card)
        out.append({**r, "related_lessons": sorted(l["id"] for l in rel)})
    doc = {"register": "runbooks", "count": len(items), "active": len(cards), "runbooks": out}
    return page(
        "Runbooks", _archive(cards, archived), f"{len(items)} runbooks, every step has a verify"
    ), json.loads(json.dumps(doc, default=str))


def render_invariants(data, results=None) -> tuple[str, dict]:
    reg = validate_invariants(data)
    res = (results or {}).get("results", {})
    titles = {p["letter"]: p["title"] for p in reg["pillars"]}
    rows, merged, counts = {}, [], {}
    for c in reg["criteria"]:
        r = res.get(c["id"], {})
        status = r.get("status") or (
            "deferred"
            if c.get("deferred")
            else "server"
            if c["evidence"] == "server"
            else "untested"
        )
        counts[status] = counts.get(status, 0) + 1
        merged.append(
            {
                **c,
                "status": status,
                "evidence_text": r.get("evidence", ""),
                "checked_at": r.get("checked_at"),
            }
        )
        cmd = c.get("observable") or c.get("plugin")
        row = (
            f'<article id="{e(c["id"])}"><h3>{e(c["id"])} <span class="pill {e(status)}">'
            f"{e(status)}</span></h3><p>{e(c['statement'])}</p>"
            + _dl(
                [
                    ("Observable", f"<code>{e(cmd)}</code>"),
                    ("Expected", e(c.get("expected"))),
                    ("Evidence", f"<pre>{e(r.get('evidence'))}</pre>" if r.get("evidence") else ""),
                    ("If red", _p(c["remediation"])),
                ]
            )
            + "</article>"
        )
        rows.setdefault(c["id"][0], []).append(row)
    body = "".join(
        f"<h2>{e(k)} - {e(titles.get(k, ''))}</h2>" + "".join(v) for k, v in sorted(rows.items())
    )
    retired = reg["retired"]
    if retired:  # tombstones: an old citation of one of these ids lands here, not on a 404
        body += "<h2>Retired ids</h2>" + "".join(
            f'<article id="{e(i)}"><h3>{e(i)} <span class="pill skip">retired</span></h3>'
            + _dl(
                [
                    (
                        "Replaced by",
                        f'<a href="#{e(t["replaced_by"])}">{e(t["replaced_by"])}</a>'
                        if t.get("replaced_by")
                        else "",
                    ),
                    ("Reason", _p(t["reason"])),
                ]
            )
            + "</article>"
            for i, t in sorted(retired.items())
        )
    red = counts.get("fail", 0) + counts.get("error", 0)
    live = [s for s in counts if s not in ("deferred", "server", "skip")]
    verdict = (
        "ALL INVARIANTS HOLD"
        if red == 0 and set(live) <= {"pass"} and live
        else f"{red} red, {counts.get('untested', 0)} untested"
    )
    summary = f"{verdict} - " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
    if results and results.get("last_run"):
        summary += f" - last run {results['last_run']}"
    doc = {
        "register": "invariants",
        "verdict": verdict,
        "counts": counts,
        "last_run": (results or {}).get("last_run"),
        "criteria": merged,
        "retired": retired,
    }
    return page("Invariants", body, summary), json.loads(json.dumps(doc, default=str))


POLICY_NAME = "review-policy.yml"


def find_policy(src: pathlib.Path) -> pathlib.Path | None:
    """``SRC/review-policy.yml`` or the one beside SRC (``examples/review-policy.yml``)."""
    return next((p for p in (src / POLICY_NAME, src.parent / POLICY_NAME) if p.is_file()), None)


def repo_root(start: pathlib.Path) -> pathlib.Path:
    """The checkout ``start`` is in (nearest ``.git``), else the working directory: repository
    paths in ``retired_by`` / ``incorporated_into`` resolve against it."""
    for d in (start.resolve(), *start.resolve().parents):
        if (d / ".git").exists():
            return d
    return pathlib.Path.cwd()


def load_sources(src_dir, policy_path=None, results_path=None) -> dict:
    """Every register of ``src_dir`` loaded and validated (fatal), plus the review policy, the
    invariants results and the repository root they were checked against."""
    from homelabnext.reviews import ReviewError, load_policy

    src = pathlib.Path(src_dir)
    pp = pathlib.Path(policy_path) if policy_path else find_policy(src)
    try:
        policy = load_policy(pp) if pp else None
    except ReviewError as ex:
        raise RegisterError("review policy", ex.problems) from None
    out: dict = {"policy": policy, "lessons": None, "runbooks": None, "invariants": None}
    if path := register_source(src, "lessons"):
        out["lessons"] = load_register(path, "lessons")
    if path := register_source(src, "runbooks"):
        out["runbooks"] = load_register(path, "runbooks")
    if (src / "invariants.yml").exists():
        out["invariants"] = load_register(src / "invariants.yml")
    rp = pathlib.Path(results_path) if results_path else src / "invariants.results.json"
    out["results"] = json.loads(rp.read_text()) if rp.exists() else None
    out["root"] = repo_root(src)
    return out


def build_all(src_dir, out_dir, results_path=None, policy_path=None) -> list[pathlib.Path]:
    """Render whichever of lessons, runbooks and invariants exist in ``src_dir``: a record
    directory (``lessons/``, ``runbooks/``) or a single file (``lessons.yml`` ...), read through
    :func:`homelabnext.registers.records.load_register`.

    Fatal: any invalid register, a reference that does not resolve (``related``,
    ``superseded_by``, ``incorporated_into``, ``retired_by``, step ``from_lessons``), or a record
    whose status lacks the reviews the review policy (``review-policy.yml`` in or beside
    ``src_dir``) requires raises RegisterError before ANY file is written, so a broken entry can
    never leave a half-updated site behind.
    """
    src, out = pathlib.Path(src_dir), pathlib.Path(out_dir)
    s = load_sources(src, policy_path, results_path)
    rendered = {}
    ll: list[dict] = []
    rb: list[dict] = []
    if s["lessons"] is not None:
        rendered["lessons"] = render_lessons(s["lessons"], s["policy"])
        ll = s["lessons"]["lessons"]
    if s["runbooks"] is not None:
        rendered["runbooks"] = render_runbooks(s["runbooks"], ll, s["policy"])
        rb = s["runbooks"]["runbooks"]
    criteria = None
    if s["invariants"] is not None:
        rendered["invariants"] = render_invariants(s["invariants"], s["results"])
        criteria = {str(c.get("id")) for c in s["invariants"]["criteria"]}
    check_links(ll, rb, criteria, s["root"])
    if not rendered:
        raise RegisterError("build", [f"no lessons/runbooks/invariants register in {src}"])
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (h, j) in rendered.items():
        for suffix, text in (
            (".html", h),
            (".json", json.dumps(j, indent=2, sort_keys=True) + "\n"),
        ):
            p = out / (name + suffix)
            if not p.exists() or p.read_text() != text:  # no-op rewrites keep mtimes/diffs quiet
                p.write_text(text)
            written.append(p)
    return written
