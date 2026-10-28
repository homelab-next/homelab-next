# SPDX-License-Identifier: Apache-2.0
"""The review tier of a change to the lab's site, its module selection and the other files that
decide what the lab trusts (``hnx site review-tier``; docs/private-overlay.md, "What a change to
the lab claims").

The default is **human approve**: a change is **owner** only where this module says why it widens
nothing.  That is the narrowing of a judged field (:data:`FIELDS`), or a change to one of the few
fields listed as widening no reach (:data:`SITE_OWNER`, :data:`ZONE_OWNER`,
:data:`SELECTION_OWNER`).  Every other changed key, of the site, a zone or the selection, is
human-approve with its path.  The judged fields, each with the reason it is on the list:

- ``delegated_prefixes6`` (site 1.5): a declared prefix is counted as the lab's by the model
  runtimes' lab-only rule, so declaring one is what lets a model runtime reach it.
- ``zones`` (a new zone) and ``zones[].subnet`` / ``zones[].subnet6`` (a changed or added range):
  a zone's ranges are what every ``zone:`` firewall allow renders to and what the lab-only rule
  counts as the lab (a private subnet, a unique-local or delegated ``subnet6``).
- ``zones[].egress``: ``internet`` turned to anything but ``deny``, ``one_way`` turned off, or any
  other egress key changed.
- ``firewall.zone_to_zone`` / ``firewall.service_exceptions``: an ``allow`` added or changed, a
  ``deny`` removed or changed, and the service exceptions reordered (first match wins, in
  document order; one rule per zone pair keeps ``zone_to_zone`` order free).
- ``tailnet``: what the CI deploy's tailnet key may reach.
- the selection's ``scope`` (``lab/modules.yml``): an address added to ``trusted`` (the lab
  itself, never an outsider; ``trusted.nets`` is the lab to the egress generator) or ``target``
  (what assessment tooling may touch), an address removed from ``exclude``, or an ``exclude``
  part declared where it was absent (absent fails closed; ``[]`` excludes nothing).
- the selection's ``grants``: any grant added (a grant is what lets a selected module reach the
  internet, publish, take shared config or a secret, run privileged units).
- the selection's ``lab_table_namespaces``: a namespace added (a gathered table there passes as
  the lab's own and is never judged), or the list removed (no unbound table is judged).
  Removing a namespace, changing only a ``why`` or declaring the list where it was absent narrows.
- the rest of the selection (``hosts``, with their ``addresses`` and ``isolated``, ``slots``,
  ``features``, ``core``, ``providers`` and their placements): any change but a host's
  ``capacity``.

Files outside the site and selection decide what the lab trusts too, and each changed one is
human-approve as a whole (:data:`TRUST_PATHS`): the registry (``lab/services.yml``, what a
``svc:`` allow renders to), the guests (``lab/guests/``: a guest's zone, addresses and
``outbound_allow``), and the overlay's own modules and lock (``lab/modules/``,
``lab/modules.lock``), the model role table (``lab/model_roles.json``: ``leaves_lab`` and
``fallback`` decide who needs ``grants.cloud_models``) and its swap records (``lab/swaps/``), which
``hnx modules review-tier`` does not read for the overlay (its roots are the
repository's ``modules/`` and ``examples/modules/``).

Everything fails closed: a file new at the head, removed from it, unreadable at either end (not
UTF-8 or YAML, a symbolic link, not a regular file, over the size cap), sealed (a top-level
``sops`` key: the values cannot be judged), with a mapping key that is not text, or a value of a
judged field whose shape cannot be compared is human-approve.

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
    "SELECTION_OWNER",
    "SITE",
    "SITE_OWNER",
    "TRUST_PATHS",
    "ZONE_OWNER",
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
    "zones[].egress": "internet other than deny, one_way off, or another key opens a zone outward",
    "firewall.zone_to_zone": "an allow lets one zone reach another",
    "firewall.service_exceptions": "an allow lets a zone reach a service; first match wins",
    "tailnet": "what the CI deploy's tailnet key reaches",
    "scope.trusted": "the lab itself: never an outsider, and the lab to the egress generator",
    "scope.target": "what assessment tooling may touch",
    "scope.exclude": "the carve-outs every reader honours",
    "grants": "what a selected module may do beyond its own slot",
    "lab_table_namespaces": "a table in a listed namespace is the lab's own and is never judged",
    "selection": "hosts (addresses, isolated), slots, features, core and providers and their "
    "placement decide what runs where and what it may reach",
}
#: the site's top-level keys that widen no reach, and why (every other changed key is human)
SITE_OWNER = {
    "site_version": "the schema version the file is written to",
    "site": "the site's id, domain and timezone: names, not reach",
    "edge": "the uplink chain's devices and their power: a description, not a rule",
    "power": "the UPSes and a device's default power",
}
#: a zone's keys that widen no reach, and why (``dhcp.lease_hours`` too; every other is human)
ZONE_OWNER = {
    "purpose": "a description",
    "tags": "labels no rule reads",
}
#: the selection's paths that widen no reach (``hosts.<host>.capacity``), and why
SELECTION_OWNER = {"hosts.*.capacity": "the resources a host offers: a limit, not reach"}
#: files and directories whose every change is human-approve as a whole, and why
TRUST_PATHS = {
    "lab/services.yml": "the registry: the hosts, addresses, ports and zones every svc: allow "
    "and route renders to",
    "lab/guests/": "a guest's zone, addresses, extra addresses and outbound_allow",
    "lab/modules/": "the overlay's own modules (manifests, roles, units), which hnx modules "
    "review-tier does not read",
    "lab/modules.lock": "what each fetched module is pinned to",
    "lab/model_roles.json": "the model role table: a binding's leaves_lab and a role's fallback "
    "decide which modules need grants.cloud_models, and no pin shows them",
    "lab/swaps/": "the swap records that cover a change to the model role table",
    "lab/model-serving/model_store.json": "the model store: what a swap's rebind vouches for",
    "lab/model_roles.eval.json": "the evaluation report a rebind's live canary must pass",
    "lab/model-evals/": "the evaluation reports that vouch for a model a swap rebinds to",
}
_FIREWALL_LISTS = ("zone_to_zone", "service_exceptions")
LAB_NAMESPACES = "lab_table_namespaces"
_TRUSTED = ("wan", "nets", "tooling")
_EXCLUDE = ("unattended_mutation", "offensive")


def _canon(value: Any) -> str:
    """A comparable text of a parsed document (its mapping keys are text: :func:`_odd_key`)."""
    return json.dumps(value, sort_keys=True, default=str)


def _odd_key(value: Any) -> bool:
    """True when a mapping anywhere in ``value`` has a key that is not text (``1:``, ``no:``):
    compared as text it could equal another key, so such a document is not judged."""
    if isinstance(value, dict):
        return any(not isinstance(k, str) or _odd_key(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_odd_key(v) for v in value)
    return False


def _diff(old: Any, new: Any, path: str) -> list[tuple[str, str]]:
    """(path, how) for each difference of ``new`` from ``old``: a mapping key ``added``,
    ``removed`` or ``changed`` below it; a list item ``added`` or ``removed`` (as a multiset), or
    the list ``reordered``; a scalar ``changed``."""
    if _canon(old) == _canon(new):
        return []
    if isinstance(old, dict) and isinstance(new, dict):
        out: list[tuple[str, str]] = []
        for k in sorted({*old, *new}):
            sub = f"{path}.{k}"
            if k not in old:
                out.append((sub, "added"))
            elif k not in new:
                out.append((sub, "removed"))
            else:
                out += _diff(old[k], new[k], sub)
        return out
    if isinstance(old, list) and isinstance(new, list):
        added, removed = _added_removed(old, new) or ([], [])
        hows = ["added"] * len(added) + ["removed"] * len(removed)
        return [(path, how) for how in dict.fromkeys(hows)] or [(path, "reordered")]
    return [(path, "changed")]


def _human(old: Any, new: Any, path: str, why: str) -> list[Change]:
    return [Change(p, HUMAN, f"{how}: {why}") for p, how in _diff(old, new, path)]


_DEFAULT = "a field not listed as widening no reach (only listed fields are owner)"


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
        where = f"zones.{zid}"
        for key in ("subnet", "subnet6"):
            if _canon(a.get(key)) == _canon(b.get(key)):
                continue
            if b.get(key) is None:
                changes.append(Change(f"{where}.{key}", OWNER, f"the zone's {key} removed"))
            else:
                changes.append(Change(f"{where}.{key}", HUMAN, FIELDS[f"zones[].{key}"]))
        changes += _egress(a.get("egress"), b.get("egress"), f"{where}.egress")
        da, db = a.get("dhcp"), b.get("dhcp")
        if _canon(da) != _canon(db):
            if not isinstance(da, dict) or not isinstance(db, dict):
                changes += _human(da, db, f"{where}.dhcp", _DEFAULT)
            else:
                for k in sorted({*da, *db}):
                    if _canon(da.get(k)) == _canon(db.get(k)):
                        continue
                    if k == "lease_hours":
                        changes.append(Change(f"{where}.dhcp.lease_hours", OWNER, "a lease time"))
                    else:
                        changes += _human(da.get(k), db.get(k), f"{where}.dhcp.{k}", _DEFAULT)
        rest = {k for k in (*a, *b) if k not in ("id", "subnet", "subnet6", "egress", "dhcp")}
        for k in sorted(rest):
            if _canon(a.get(k)) == _canon(b.get(k)):
                continue
            if k in ZONE_OWNER:
                changes.append(Change(f"{where}.{k}", OWNER, ZONE_OWNER[k]))
            else:
                changes += _human(a.get(k), b.get(k), f"{where}.{k}", _DEFAULT)
    return changes


def _egress(old: Any, new: Any, where: str) -> list[Change]:
    """``internet`` other than exactly ``deny`` widens (the schema's enum is only enforced where
    the site is validated, and this check does not validate it), ``one_way`` off widens, any
    other key changed widens; ``internet: deny`` and ``one_way`` on narrow."""
    if _canon(old) == _canon(new):
        return []
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [_fail(where, "not a mapping at both ends")]
    changes: list[Change] = []
    for k in sorted({*old, *new}):
        a, b = old.get(k), new.get(k)
        if _canon(a) == _canon(b):
            continue
        if k == "internet":
            wider = b != "deny"
        elif k == "one_way":
            wider = a is True and b is not True
        else:
            changes += _human(a, b, f"{where}.{k}", FIELDS["zones[].egress"])
            continue
        if wider:
            changes.append(Change(where, HUMAN, FIELDS["zones[].egress"]))
        else:
            changes.append(Change(where, OWNER, "narrows the zone's egress"))
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
        if key == "service_exceptions" and not added and not removed:
            if _canon(o.get(key) or []) != _canon(n.get(key) or []):
                changes.append(Change(field, HUMAN, "reordered: first match wins"))
            continue
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
    if early := _unjudged("site", o, n):
        return early
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
        if k in SITE_OWNER:
            changes.append(Change(k, OWNER, SITE_OWNER[k]))
        else:
            changes += _human(o.get(k), n.get(k), k, _DEFAULT)
    return changes


def _unjudged(name: str, o: dict, n: dict) -> list[Change]:
    """A human-approve change when either end cannot be judged: sealed, or a key not text."""
    if "sops" in o or "sops" in n:
        return [_fail(name, "sealed: cannot judge")]
    if _odd_key(o) or _odd_key(n):
        return [_fail(name, "a mapping key that is not text")]
    return []


# ------------------------------------------------------------------------------- the selection


def scope_changes(old: Any, new: Any) -> list[Change]:
    """The tiered changes from module selection ``old`` to ``new`` (None is an absent
    selection): its ``scope`` and ``grants`` by their rules, every other key human-approve but a
    host's ``capacity``."""
    o = {} if old is None else old
    n = {} if new is None else new
    if not isinstance(o, dict) or not isinstance(n, dict):
        return [_fail("selection", f"not a mapping ({_shape(old)} to {_shape(new)})")]
    if early := _unjudged("selection", o, n):
        return early
    return _scope(o, n) + _grants(o, n) + _lab_namespaces(o, n) + _selection_rest(o, n)


def _selection_rest(o: dict, n: dict) -> list[Change]:
    changes: list[Change] = []
    for k in sorted({*o, *n} - {"scope", "grants", LAB_NAMESPACES}):
        for path, how in _diff(o.get(k), n.get(k), k):
            parts = path.split(".")
            if len(parts) >= 3 and parts[0] == "hosts" and parts[2] == "capacity":
                changes.append(Change(path, OWNER, SELECTION_OWNER["hosts.*.capacity"]))
            else:
                changes.append(Change(path, HUMAN, f"{how}: {FIELDS['selection']}"))
    return changes


def _scope(o: dict, n: dict) -> list[Change]:
    changes: list[Change] = []
    so = {} if o.get("scope") is None else o.get("scope")
    sn = {} if n.get("scope") is None else n.get("scope")
    if not isinstance(so, dict) or not isinstance(sn, dict):
        return [_fail("scope", "not a mapping at both ends")]
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
    return changes


def _lab_namespaces(o: dict, n: dict) -> list[Change]:
    """A namespace added is human (its tables pass as the lab's), and so is the list removed
    (no unbound table is judged); a namespace removed, a ``why`` changed or the list declared
    where it was absent narrows."""
    key = LAB_NAMESPACES
    unchanged = (key in o) == (key in n) and _canon(o.get(key)) == _canon(n.get(key))
    if unchanged and o.get(key, []) is not None:  # a null list fails closed even unchanged
        return []

    def index(side: dict) -> dict[str, Any] | None:
        # absent is empty; present and null is no list (the schema refuses it too)
        entries = side.get(key, [])
        if not isinstance(entries, list):
            return None
        out: dict[str, Any] = {}
        for e in entries:
            ns = e.get("namespace") if isinstance(e, dict) else None
            if not isinstance(ns, str) or ns in out:
                return None
            out[ns] = e.get("why")
        return out

    io, inew = index(o), index(n)
    if io is None or inew is None:
        return [_fail(key, "not a list of distinct {namespace, why} at both ends")]
    if key not in n:
        return [Change(key, HUMAN, "the lab's namespaces no longer declared: no table is judged")]
    if key not in o:
        return [Change(key, OWNER, "the lab's namespaces declared: every other one is judged")]
    changes = [Change(f"{key}.{ns}", HUMAN, FIELDS[key]) for ns in sorted(inew.keys() - io)]
    changes += [
        Change(f"{key}.{ns}", OWNER, "a namespace no longer the lab's")
        for ns in sorted(io.keys() - inew)
    ]
    changes += [
        Change(f"{key}.{ns}.why", OWNER, "a description")
        for ns in sorted(io.keys() & inew.keys())
        if _canon(io[ns]) != _canon(inew[ns])
    ]
    return changes


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
    for rel in se.changed_paths(root, sha, list(TRUST_PATHS)):
        why = next(w for p, w in TRUST_PATHS.items() if rel == p or rel.startswith(p))
        results.append(Result(rel, [Change(rel, HUMAN, f"changed: {why}")]))
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
