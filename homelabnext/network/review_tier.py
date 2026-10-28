# SPDX-License-Identifier: Apache-2.0
"""The review tier of a change to the lab's site and module selection (``hnx site review-tier``;
docs/private-overlay.md, "What a change to the lab claims").

A few site fields widen what the lab trusts or what a guest may reach.  A change that widens one
needs a **human approve**; every other change, and every narrowing of one, needs only the
**owner**.  The fields, each with the reason it is on the list (:data:`FIELDS`):

- ``delegated_prefixes6`` (site 1.5): a declared prefix is counted as the lab's by the model
  runtimes' lab-only rule, so declaring one is what lets a model runtime reach it.
- ``zones`` (a new zone) and ``zones[].subnet`` / ``zones[].subnet6`` (a changed or added range):
  a zone's ranges are what every ``zone:`` firewall allow renders to and what the lab-only rule
  counts as the lab (a private subnet, a unique-local or delegated ``subnet6``).
- ``zones[].egress``: ``internet`` turned to ``allow``, or ``one_way`` turned off.
- ``firewall.zone_to_zone`` / ``firewall.service_exceptions``: an ``allow`` added or changed, or a
  ``deny`` removed or changed.
- ``tailnet``: what the CI deploy's tailnet key may reach.
- the selection's ``scope`` (``lab/modules.yml``): an address added to ``trusted`` (the lab
  itself, never an outsider; ``trusted.nets`` is the lab to the egress generator) or ``target``
  (what assessment tooling may touch), an address removed from ``exclude``, or an ``exclude``
  part declared where it was absent (absent fails closed; ``[]`` excludes nothing).
- the selection's ``grants``: any grant added (a grant is what lets a selected module reach the
  internet, publish, take shared config or a secret, run privileged units).

Everything fails closed: a file new at the head, removed from it, unreadable at either end
(not UTF-8 or YAML, a symbolic link, not a regular file, over the size cap), or a value of a
listed field whose shape cannot be compared is human-approve.

**What enforces the approval** is not this check.  Like ``hnx modules review-tier`` it reports
every change with its tier and fails (exit 1) only when a human-approve change has **no valid
CODEOWNERS owner as of the base**: the approval itself is the pull request's code-owner review,
which binds only where the branch rules require it.  Without that rule a human-approve change is
merely visible (in the job log and the step summary); this check does not read approvals and
authenticates no reviewer.

The base is read through git (:mod:`homelabnext.modules.swap_evidence`: one resolved commit,
``--no-replace-objects``, capped regular blobs), the head from the working tree the way the
loader reads every input.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from homelabnext.modules import loader as ld
from homelabnext.modules import review_tier as rt
from homelabnext.modules import swap_evidence as se

__all__ = [
    "FIELDS",
    "HUMAN",
    "OWNER",
    "SELECTION",
    "SITE",
    "Change",
    "Result",
    "review",
    "scope_changes",
    "site_changes",
]

HUMAN = rt.HUMAN
OWNER = rt.OWNER
Change = rt.Change
Result = rt.Result
#: the overlay's site and module selection, relative to its root
SITE = "lab/site.yml"
SELECTION = "lab/modules.yml"
#: the trust-widening fields this check judges, and why each widens (the module docstring)
FIELDS = {
    "delegated_prefixes6": "a declared prefix is the lab's to the model runtimes' lab-only rule",
    "zones": "a new zone is a new range every zone: allow and the lab-only rule count as the lab",
    "zones[].subnet": "the range a zone: allow renders to, and the lab to the lab-only rule",
    "zones[].subnet6": "the range a zone: allow renders to, and the lab to the lab-only rule",
    "zones[].egress": "internet: allow, or one_way off, opens a zone outward",
    "firewall.zone_to_zone": "an allow lets one zone reach another",
    "firewall.service_exceptions": "an allow lets a zone reach a service",
    "tailnet": "what the CI deploy's tailnet key reaches",
    "scope.trusted": "the lab itself: never an outsider, and the lab to the egress generator",
    "scope.target": "what assessment tooling may touch",
    "scope.exclude": "the carve-outs every reader honours",
    "grants": "what a selected module may do beyond its own slot",
}
_FIREWALL_LISTS = ("zone_to_zone", "service_exceptions")
_TRUSTED = ("wan", "nets", "tooling")
_EXCLUDE = ("unattended_mutation", "offensive")


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _shape(value: Any) -> str:
    return type(value).__name__


def _added_removed(old: Any, new: Any) -> tuple[list[Any], list[Any]] | None:
    """The entries of list ``new`` not in list ``old`` and the reverse, as a multiset (order is
    not a change); an absent list is empty; None when either is not a list."""
    o = [] if old is None else old
    n = [] if new is None else new
    if not isinstance(o, list) or not isinstance(n, list):
        return None
    co, cn = Counter(_canon(x) for x in o), Counter(_canon(x) for x in n)
    by = {_canon(x): x for x in (*o, *n)}
    return [by[k] for k in sorted((cn - co).elements())], [
        by[k] for k in sorted((co - cn).elements())
    ]


def _leaves(value: Any, path: tuple[str, ...] = ()) -> set[tuple[tuple[str, ...], str]]:
    """Every scalar under ``value`` with the mapping keys leading to it (a list's items share
    their list's path, so order is not a change)."""
    if isinstance(value, dict):
        out: set[tuple[tuple[str, ...], str]] = set()
        for k, v in value.items():
            out |= _leaves(v, (*path, str(k)))
        return out
    if isinstance(value, list):
        out = set()
        for v in value:
            out |= _leaves(v, path)
        return out
    return {(path, _canon(value))}


def _fail(field: str, why: str) -> Change:
    return Change(field, HUMAN, f"{why} (fail closed)")


# ------------------------------------------------------------------------------- the site


def _zones(old: Any, new: Any) -> list[Change]:
    def index(zones: Any) -> dict[str, Any] | None:
        if zones is None:
            return {}
        if not isinstance(zones, list):
            return None
        out: dict[str, Any] = {}
        for z in zones:
            zid = z.get("id") if isinstance(z, dict) else None
            if not isinstance(zid, str) or zid in out:
                return None
            out[zid] = z
        return out

    o, n = index(old), index(new)
    if o is None or n is None:
        return [_fail("zones", "not a list of zones with distinct ids")]
    changes: list[Change] = []
    for zid in sorted(n.keys() - o.keys()):
        changes.append(Change(f"zones.{zid}", HUMAN, FIELDS["zones"]))
    for zid in sorted(o.keys() - n.keys()):
        changes.append(Change(f"zones.{zid}", OWNER, "a zone removed"))
    for zid in sorted(o.keys() & n.keys()):
        a, b = o[zid], n[zid]
        for key in ("subnet", "subnet6"):
            if _canon(a.get(key)) == _canon(b.get(key)):
                continue
            if b.get(key) is None:
                changes.append(Change(f"zones.{zid}.{key}", OWNER, f"the zone's {key} removed"))
            else:
                changes.append(Change(f"zones.{zid}.{key}", HUMAN, FIELDS[f"zones[].{key}"]))
        ea, eb = a.get("egress"), b.get("egress")
        if _canon(ea) != _canon(eb):
            if not isinstance(ea, dict) or not isinstance(eb, dict):
                changes.append(_fail(f"zones.{zid}.egress", "not a mapping at both ends"))
            elif (eb.get("internet") == "allow" and ea.get("internet") != "allow") or (
                ea.get("one_way") is True and eb.get("one_way") is not True
            ):
                changes.append(Change(f"zones.{zid}.egress", HUMAN, FIELDS["zones[].egress"]))
            else:
                changes.append(Change(f"zones.{zid}.egress", OWNER, "narrows the zone's egress"))
        rest = {k for k in (*a, *b) if k not in ("id", "subnet", "subnet6", "egress")}
        if any(_canon(a.get(k)) != _canon(b.get(k)) for k in rest):
            changes.append(Change(f"zones.{zid}", OWNER, "a field that widens no reach"))
    return changes


def _firewall(old: Any, new: Any) -> list[Change]:
    o = {} if old is None else old
    n = {} if new is None else new
    if not isinstance(o, dict) or not isinstance(n, dict):
        return [_fail("firewall", "not a mapping at both ends")]
    changes: list[Change] = []
    for key in _FIREWALL_LISTS:
        diff = _added_removed(o.get(key), n.get(key))
        field = f"firewall.{key}"
        if diff is None:
            changes.append(_fail(field, "not a list at both ends"))
            continue
        added, removed = diff
        for e in added:
            action = e.get("action") if isinstance(e, dict) else None
            if action == "deny":
                changes.append(Change(field, OWNER, "a deny added"))
            else:
                changes.append(Change(field, HUMAN, f"{FIELDS[field]}: an allow added or changed"))
        for e in removed:
            action = e.get("action") if isinstance(e, dict) else None
            if action == "allow":
                changes.append(Change(field, OWNER, "an allow removed"))
            else:
                changes.append(
                    Change(field, HUMAN, "a deny removed or changed: what it denied may be allowed")
                )
    rest = {k for k in (*o, *n) if k not in _FIREWALL_LISTS}
    if any(_canon(o.get(k)) != _canon(n.get(k)) for k in rest):
        changes.append(_fail("firewall", "a firewall field this check does not judge"))
    return changes


def site_changes(old: Any, new: Any) -> list[Change]:
    """The tiered changes from site document ``old`` to ``new`` (None is an absent document)."""
    o = {} if old is None else old
    n = {} if new is None else new
    if not isinstance(o, dict) or not isinstance(n, dict):
        return [_fail("site", f"not a mapping ({_shape(old)} to {_shape(new)})")]
    changes: list[Change] = []
    diff = _added_removed(o.get("delegated_prefixes6"), n.get("delegated_prefixes6"))
    if diff is None:
        changes.append(_fail("delegated_prefixes6", "not a list at both ends"))
    else:
        for e in diff[0]:
            p = e.get("prefix") if isinstance(e, dict) else e
            changes.append(Change(f"delegated_prefixes6.{p}", HUMAN, FIELDS["delegated_prefixes6"]))
        for e in diff[1]:
            p = e.get("prefix") if isinstance(e, dict) else e
            changes.append(Change(f"delegated_prefixes6.{p}", OWNER, "a delegated prefix removed"))
    changes += _zones(o.get("zones"), n.get("zones"))
    changes += _firewall(o.get("firewall"), n.get("firewall"))
    if _canon(o.get("tailnet")) != _canon(n.get("tailnet")):
        changes.append(Change("tailnet", HUMAN, FIELDS["tailnet"]))
    judged = {"delegated_prefixes6", "zones", "firewall", "tailnet"}
    rest = sorted(k for k in {*o, *n} - judged if _canon(o.get(k)) != _canon(n.get(k)))
    for k in rest:
        changes.append(Change(str(k), OWNER, "a field that widens no reach"))
    return changes


# ------------------------------------------------------------------------------- the selection


def scope_changes(old: Any, new: Any) -> list[Change]:
    """The tiered changes to the ``scope`` and ``grants`` of module selection ``old`` to ``new``
    (None is an absent selection); the rest of a selection is the loader's to check."""
    o = {} if old is None else old
    n = {} if new is None else new
    if not isinstance(o, dict) or not isinstance(n, dict):
        return [_fail("selection", f"not a mapping ({_shape(old)} to {_shape(new)})")]
    changes: list[Change] = []
    so = {} if o.get("scope") is None else o.get("scope")
    sn = {} if n.get("scope") is None else n.get("scope")
    if not isinstance(so, dict) or not isinstance(sn, dict):
        return [_fail("scope", "not a mapping at both ends"), *_grants(o, n)]
    to = {} if so.get("trusted") is None else so.get("trusted")
    tn = {} if sn.get("trusted") is None else sn.get("trusted")
    if not isinstance(to, dict) or not isinstance(tn, dict):
        changes.append(_fail("scope.trusted", "not a mapping at both ends"))
    else:
        for part in sorted({*to, *tn}):
            field = f"scope.trusted.{part}"
            diff = _added_removed(to.get(part), tn.get(part)) if part in _TRUSTED else None
            if diff is None:
                if _canon(to.get(part)) != _canon(tn.get(part)):
                    changes.append(_fail(field, "a part this check does not know, or not a list"))
                continue
            changes += [Change(field, HUMAN, FIELDS["scope.trusted"]) for _ in diff[0]]
            changes += [Change(field, OWNER, "an address no longer trusted") for _ in diff[1]]
    diff = _added_removed(so.get("target"), sn.get("target"))
    if diff is None:
        changes.append(_fail("scope.target", "not a list at both ends"))
    else:
        changes += [Change("scope.target", HUMAN, FIELDS["scope.target"]) for _ in diff[0]]
        changes += [Change("scope.target", OWNER, "an address no longer a target") for _ in diff[1]]
    eo, en = so.get("exclude"), sn.get("exclude")
    if _canon(eo) != _canon(en):
        eo_d = {} if eo is None else eo
        en_d = {} if en is None else en
        if not isinstance(eo_d, dict) or not isinstance(en_d, dict):
            changes.append(_fail("scope.exclude", "not a mapping at both ends"))
        else:
            for part in sorted({*eo_d, *en_d}):
                field = f"scope.exclude.{part}"
                a, b = eo_d.get(part), en_d.get(part)
                if _canon(a) == _canon(b):
                    continue
                if part not in _EXCLUDE:
                    changes.append(_fail(field, "a part this check does not know"))
                elif b is None:
                    changes.append(Change(field, OWNER, "absent: every reader fails closed"))
                elif a is None:
                    changes.append(
                        Change(
                            field,
                            HUMAN,
                            f"{FIELDS['scope.exclude']}: declared where absent failed closed",
                        )
                    )
                elif (diff := _added_removed(a, b)) is None:
                    changes.append(_fail(field, "not a list at both ends"))
                else:
                    changes += [
                        Change(
                            field,
                            HUMAN,
                            f"{FIELDS['scope.exclude']}: an address no longer excluded",
                        )
                        for _ in diff[1]
                    ]
                    changes += [Change(field, OWNER, "an address excluded") for _ in diff[0]]
    rest = {k for k in (*so, *sn) if k not in ("trusted", "target", "exclude")}
    if any(_canon(so.get(k)) != _canon(sn.get(k)) for k in rest):
        changes.append(_fail("scope", "a scope part this check does not judge"))
    return changes + _grants(o, n)


def _grants(o: dict, n: dict) -> list[Change]:
    go, gn = o.get("grants"), n.get("grants")
    if _canon(go) == _canon(gn):
        return []
    if not isinstance(go or {}, dict) or not isinstance(gn or {}, dict):
        return [_fail("grants", "not a mapping at both ends")]
    added = _leaves(gn or {}) - _leaves(go or {})
    if added:
        paths = sorted({".".join(("grants", *p)) for p, _ in added})
        return [Change(p, HUMAN, FIELDS["grants"]) for p in paths]
    return [Change("grants", OWNER, "a grant removed")]


# ------------------------------------------------------------------------------- the review


def _parse(data: bytes) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ld.Unreadable("not UTF-8") from None
    return ld.parse_yaml(text)


def _version(read: Callable[[], bytes | None], where: str) -> tuple[Any, str | None]:
    """(the parsed document or None for an absent one, why it cannot be read or None)."""
    try:
        data = read()
    except (se.EvidenceError, OSError) as exc:
        return None, f"{where}: {exc}"
    if data is None:
        return None, None
    try:
        return _parse(data), None
    except (ld.Unreadable, ValueError) as exc:
        return None, f"{where}: {exc}"


def review(
    root: Path, base: str | None, *, site: str = SITE, selection: str = SELECTION
) -> tuple[list[Result], list[str]]:
    """(each changed file's tiered changes and owners, the problems: a human-approve change with
    no valid code owner as of ``base``, or CODEOWNERS unreadable there).  ``base`` None is a
    root commit: every file is new.  A ``base`` that is not a commit raises EvidenceError."""
    sha = se.resolve_base(root, base) if base is not None else None
    problems: list[str] = []
    results: list[Result] = []
    for rel, judge in ((site, site_changes), (selection, scope_changes)):

        def at_base(rel=rel):
            return se.read_base(root, sha, rel, missing_ok=True) if sha else None

        old, old_err = _version(at_base, f"{rel} at {(sha or 'the root')[:12]}")
        new, new_err = _version(lambda rel=rel: se.read_head(root, rel), rel)
        if old_err or new_err:
            results.append(Result(rel, [_fail(rel, old_err or new_err or "")]))
            continue
        if old is None and new is None:
            continue
        if sha and old is None:
            changes = [_fail(rel, "new in this change"), *judge(None, new)]
        elif new is None:
            changes = [_fail(rel, "removed in this change")]
        else:
            changes = judge(old, new)
        if changes:
            results.append(Result(rel, changes))
    rules: list[tuple[str, list[str]]] = []
    owners_from = None
    for rel in rt.CODEOWNERS_PATHS:
        if sha is None:
            break
        try:
            data = se.read_base(root, sha, rel, missing_ok=True)
        except se.EvidenceError as exc:
            problems.append(f"{rel}: {exc}, so no change has a code owner")
            owners_from = rel
            break
        if data is not None:
            owners_from = rel
            try:
                rules = rt.parse_codeowners(data.decode("utf-8"))
            except UnicodeDecodeError:
                problems.append(f"{rel} at {sha[:12]}: not UTF-8, so no change has a code owner")
            break
    for r in results:
        r.owners = rt.codeowners_for(rules, r.path)
        if r.tier == HUMAN and not r.owners:
            problems.append(
                f"{r.path}: a human-approve change, and no valid CODEOWNERS owner as of "
                f"{(sha or 'the root commit')[:12]} ({owners_from or 'no CODEOWNERS file'}) "
                "whose review approves it"
            )
    return results, problems
