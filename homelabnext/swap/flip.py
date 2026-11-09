# SPDX-License-Identifier: Apache-2.0
"""The cutover flip and the promotion: one reviewed change to the registry document.

Consumers resolve ``<capability>.<svc_label>.<domain>``; the registry row behind that alias says
which host, port and implementation answer. Cutover is therefore one reviewed change to that row
(ADR-0002, ADR-0005), and rollback is the same change reversed.

:func:`plan_flip` is a pure function on a parsed registry document. It validates the result with
the registry's own rules and returns a :class:`FlipPlan` carrying the diff and its exact
:meth:`~FlipPlan.inverse`. :func:`flip_text` applies a plan to the YAML *text*, touching only the
changed scalar lines (comments and layout survive) and proving the result equals the plan.

A flip moves the same product (host, port, version).  Replacing the product behind a capability
is a promotion (ADR-0039 decision 6): :func:`plan_promote` makes an ``eval`` row the primary and
the incumbent ``retiring`` (or ``legacy``) with ``until`` derived from the ledger's rollback
window, as one :class:`PromotePlan` with an exact inverse; :func:`promote_text` writes it.  Once a
capability has a non-primary row, :func:`plan_flip` refuses an ``impl`` change on it.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml

from homelabnext.registry.model import RegistryError, _UniqueKeyLoader, build_registry

FLIPPABLE = ("host", "port", "impl", "version")


class FlipError(Exception):
    """The flip cannot be planned or applied safely."""


@dataclass(frozen=True)
class Change:
    path: str  # services.<name>.<field>
    before: Any
    after: Any
    #: a promotion's text edit only: the field this one follows in its row, where it is written
    #: back when it reappears (None: last), so a removal's inverse is byte-exact
    anchor: str | None = None


@dataclass(frozen=True)
class FlipPlan:
    service: str
    capability: str
    alias: str
    changes: tuple[Change, ...]
    old_target: str
    new_target: str

    @property
    def empty(self) -> bool:
        return not self.changes

    def inverse(self) -> FlipPlan:
        return FlipPlan(
            self.service,
            self.capability,
            self.alias,
            tuple(Change(c.path, c.after, c.before) for c in self.changes),
            self.new_target,
            self.old_target,
        )

    def diff(self) -> str:
        lines = [f"flip {self.service} (alias {self.alias})"]
        for c in self.changes:
            lines.append(f"  {c.path}: {c.before} -> {c.after}")
        lines.append(f"  target: {self.old_target} -> {self.new_target}")
        return "\n".join(lines) + "\n"

    def apply(self, doc: Mapping[str, Any]) -> dict[str, Any]:
        """Return a copy of ``doc`` with the changes made; refuse if ``before`` does not match."""
        return _changed(doc, self.changes, validate=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "capability": self.capability,
            "alias": self.alias,
            "changes": [
                {"path": c.path, "before": c.before, "after": c.after} for c in self.changes
            ],
            "old_target": self.old_target,
            "new_target": self.new_target,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> FlipPlan:
        return cls(
            d["service"],
            d["capability"],
            d["alias"],
            tuple(Change(c["path"], c["before"], c["after"]) for c in d["changes"]),
            d["old_target"],
            d["new_target"],
        )


def _changed(
    doc: Mapping[str, Any], changes: tuple[Change, ...], *, validate: bool = False
) -> dict[str, Any]:
    """A copy of ``doc`` with each change made (``after`` None removes the field), refused when a
    field does not read what the plan expects (the registry changed since the plan was made) and,
    with ``validate``, when the result is not a valid registry."""
    out = copy.deepcopy(dict(doc))
    for c in changes:
        _, name, fld = c.path.split(".")
        row = out.get("services", {}).get(name)
        if row is None:
            raise FlipError(f"no service {name!r} in the registry")
        if row.get(fld) != c.before:
            shown = (_show(row.get(fld)), _show(c.before))
            raise FlipError(
                f"{c.path} is {shown[0]}, the plan expects {shown[1]}; "
                "the registry changed since the plan was made"
            )
        if c.after is None:
            row.pop(fld, None)
        else:
            row[fld] = copy.deepcopy(c.after)
    if validate:
        _validate(out)
    return out


def load_doc(text: str) -> dict[str, Any]:
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise FlipError(f"registry is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise FlipError("registry root must be a mapping")
    return doc


def _validate(doc: dict[str, Any]) -> Any:
    try:
        return build_registry(copy.deepcopy(doc))
    except RegistryError as exc:
        raise FlipError(f"the flipped registry would be invalid: {exc}") from exc


def _target(doc: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    """host:port, never an address: records and diffs must not carry raw endpoints."""
    return f"{row['host']}:{row['port']}"


def plan_flip(
    doc: Mapping[str, Any],
    service: str,
    *,
    host: str | None = None,
    port: int | None = None,
    impl: str | None = None,
    version: str | None = None,
) -> FlipPlan:
    """Plan retargeting ``service``. Only the named fields change; the result must validate."""
    reg = _validate(dict(doc))  # the starting point must be valid too
    row = doc.get("services", {}).get(service)
    if row is None:
        raise FlipError(f"no service {service!r} in the registry")
    if impl is not None and impl != row.get("impl"):
        from homelabnext.registry.model import standing_of

        others = sorted(
            n
            for n, s in doc.get("services", {}).items()
            if s.get("capability") == row["capability"] and standing_of(s) != "primary"
        )
        if others:
            raise FlipError(
                f"{row['capability']} has a non-primary row ({', '.join(others)}): a change of "
                "impl there is a promotion of the candidate (plan_promote), not a flip "
                "(ADR-0039 decision 6)"
            )
    want = {"host": host, "port": port, "impl": impl, "version": version}
    changes = []
    for field in FLIPPABLE:
        new = want[field]
        if new is None:
            continue
        if field == "host" and new not in doc.get("hosts", {}):
            raise FlipError(f"host {new!r} is not in the registry; register it before the flip")
        old = row.get(field)
        if old != new:
            changes.append(Change(f"services.{service}.{field}", old, new))
    plan = FlipPlan(
        service,
        row["capability"],
        reg.alias(row["capability"]),
        tuple(changes),
        _target(doc, row),
        "",
    )
    new_doc = plan.apply(doc)
    plan = FlipPlan(
        plan.service,
        plan.capability,
        plan.alias,
        plan.changes,
        plan.old_target,
        _target(new_doc, new_doc["services"][service]),
    )
    return plan


_KEY = re.compile(r"^(?P<indent> +)(?P<key>[A-Za-z_][\w-]*):(?P<sp>[ \t]*)(?P<val>.*)$")


def _render(old_raw: str, new: Any) -> str:
    """Render ``new`` in the quoting style of the raw old value, keeping a trailing comment."""
    m = re.match(r"^(?P<v>\"[^\"]*\"|'[^']*'|[^#]*?)(?P<c>\s+#.*)?$", old_raw)
    v, c = (m.group("v"), m.group("c") or "") if m else (old_raw, "")
    if isinstance(new, bool) or not isinstance(new, str):
        text = yaml.safe_dump(new, default_flow_style=True).split("\n")[0]
    elif v.startswith('"'):
        text = f'"{new}"'
    elif v.startswith("'"):
        text = f"'{new}'"
    else:
        text = new if yaml.safe_load(new) == new else f'"{new}"'
    return text + c


def flip_text(text: str, plan: FlipPlan) -> str:
    """Apply ``plan`` to registry YAML text, editing only the changed lines."""
    lines = text.split("\n")
    in_services = False
    in_block = False
    done: set[str] = set()
    for i, line in enumerate(lines):
        if re.match(r"^services:\s*(#.*)?$", line):
            in_services = True
            continue
        if not in_services:
            continue
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_services = in_block = False
            continue
        m = _KEY.match(line)
        if not m:
            continue
        if len(m.group("indent")) == 2:
            in_block = m.group("key") == plan.service
            continue
        if in_block and len(m.group("indent")) == 4:
            path = f"services.{plan.service}.{m.group('key')}"
            for c in plan.changes:
                if c.path == path:
                    lines[i] = (
                        f"{m.group('indent')}{m.group('key')}:{m.group('sp') or ' '}"
                        + _render(m.group("val"), c.after)
                    )
                    done.add(path)
    missing = [c.path for c in plan.changes if c.path not in done]
    if missing:
        raise FlipError(f"cannot edit {missing} in place (not block-style scalars?)")
    out = "\n".join(lines)
    if load_doc(out) != plan.apply(load_doc(text)):
        raise FlipError("text edit does not reproduce the planned document; refusing to write it")
    return out


# --- promotion: the standing half of a switch (ADR-0039 decision 6) ---------------------------

#: the fields only a capability's primary may carry; they move to the new primary at a switch,
#: so consumers keep the public route and the override variable they read (ADR-0039 decision 2)
PRIMARY_ONLY = ("public_hostname", "env_var")
_STANDING_ORDER = ("tier", "until", "why")
#: the longest rollback window a promotion takes.  Until ADR-0043's ledger binds the window to
#: the service's ledger row (``rollback_days``, 14 by default), a window is only bounded here: a
#: stopped incumbent kept restorable for a year is a second product nobody runs
MAX_ROLLBACK_DAYS = 90
#: every field a promotion changes, on its candidate and its incumbent only
PROMOTION_FIELDS = ("standing", *PRIMARY_ONLY, "tlp_ceiling")


@dataclass(frozen=True)
class PromotePlan:
    """One promotion as data: ``row`` becomes the primary of ``capability`` and ``incumbent`` (the
    former primary, or None when the capability had none) takes ``incumbent_tier`` until
    ``until``.  Each change sets or removes one field of one row (``None`` is absent), so the
    plan is exactly reversible: :meth:`inverse` is the rollback."""

    capability: str
    row: str
    incumbent: str | None
    incumbent_tier: str
    switched_on: str
    rollback_days: int
    until: str
    changes: tuple[Change, ...]
    reverted: bool = False

    def inverse(self) -> PromotePlan:
        return PromotePlan(
            self.capability,
            self.row,
            self.incumbent,
            self.incumbent_tier,
            self.switched_on,
            self.rollback_days,
            self.until,
            tuple(Change(c.path, c.after, c.before, c.anchor) for c in self.changes),
            not self.reverted,
        )

    def diff(self) -> str:
        what = "revert the promotion of" if self.reverted else "promote"
        lines = [
            f"{what} {self.row} to primary of {self.capability} (switched {self.switched_on}, "
            f"rollback window {self.rollback_days} days, until {self.until})"
        ]
        lines += [f"  {c.path}: {_show(c.before)} -> {_show(c.after)}" for c in self.changes]
        return "\n".join(lines) + "\n"

    def apply(self, doc: Mapping[str, Any]) -> dict[str, Any]:
        """A copy of ``doc`` with the changes made; refused when a field does not read what the
        plan expects (the registry changed since the plan was made) or the result is invalid."""
        out = _changed(doc, self.changes, validate=True)
        want = self.incumbent if self.reverted else self.row
        have = _primaries(out, self.capability)
        if want is not None and have != [want]:
            raise FlipError(_primary_problem(self.capability, have, want))
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "row": self.row,
            "incumbent": self.incumbent,
            "incumbent_tier": self.incumbent_tier,
            "switched_on": self.switched_on,
            "rollback_days": self.rollback_days,
            "until": self.until,
            "changes": [
                {"path": c.path, "before": c.before, "after": c.after, "anchor": c.anchor}
                for c in self.changes
            ],
            "reverted": self.reverted,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> PromotePlan:
        """The plan :meth:`to_dict` wrote, as read: it is **not** validated or checked against
        any registry.  A plan from outside is trusted only after ``apply_switch`` (or the caller)
        recomputes it with :func:`plan_promote` and finds it identical."""
        return cls(
            d["capability"],
            d["row"],
            d["incumbent"],
            d["incumbent_tier"],
            d["switched_on"],
            d["rollback_days"],
            d["until"],
            tuple(
                Change(c["path"], c["before"], c["after"], c.get("anchor")) for c in d["changes"]
            ),
            d.get("reverted", False),
        )


def _show(v: Any) -> str:
    return "(absent)" if v is None else _flow(v) if isinstance(v, Mapping) else repr(v)


def _primaries(doc: Mapping[str, Any], capability: str) -> list[str]:
    from homelabnext.registry.model import standing_of

    return sorted(
        n
        for n, s in doc.get("services", {}).items()
        if s.get("capability") == capability and standing_of(s) == "primary"
    )


def _primary_problem(capability: str, have: list[str], want: str) -> str:
    if not have:
        return f"the promotion would leave {capability} with no primary (expected {want})"
    if len(have) > 1:
        return f"the promotion would leave {capability} with two primaries: {', '.join(have)}"
    return f"the promotion would make {have[0]} the primary of {capability}, not {want}"


def _lowered_ceiling(
    capability: str, inc: Mapping[str, Any], cand: Mapping[str, Any]
) -> str | None:
    """The ``tlp_ceiling`` an egress incumbent takes as it leaves primacy, or None to keep its
    own.  A non-primary egress row may not sit above the primary's ceiling (ADR-0033 decision 6),
    and the incumbent is stopped, so it is lowered to the new primary's; the inverse restores it.
    (A registry whose eval row declares a ceiling and whose primary declares none is refused
    before any plan, so both are present here or the registry's own rule answers.)"""
    from homelabnext import tlp
    from homelabnext.registry.model import EGRESS_CAPABILITIES

    if capability not in EGRESS_CAPABILITIES:
        return None
    mine, theirs = inc.get("tlp_ceiling"), cand.get("tlp_ceiling")
    if not mine or not theirs:
        return None
    try:
        above = tlp.parse_stored(mine) > tlp.parse_stored(theirs)
    except ValueError:
        return None
    return theirs if above else None


def _before_key(row: Mapping[str, Any], fld: str) -> str | None:
    keys = list(row)
    i = keys.index(fld) if fld in keys else 0
    return keys[i - 1] if i > 0 else None


def _date(value: dt.date | str) -> dt.date:
    if isinstance(value, dt.datetime):
        raise FlipError("switched_on is a date (YYYY-MM-DD), not a time")
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        raise FlipError(f"switched_on {value!r} is not a date (YYYY-MM-DD)") from None


def plan_promote(
    doc: Mapping[str, Any],
    capability: str,
    row: str,
    switched_on: dt.date | str,
    rollback_days: int,
    *,
    old_lab: bool = False,
    why: str | None = None,
) -> PromotePlan:
    """Plan the standing half of a switch (ADR-0039 decision 6, ADR-0040 decision 5 step 6).

    The ``eval`` row ``row`` becomes the primary of ``capability``; the incumbent primary becomes
    ``retiring`` (``legacy`` with ``old_lab``: an old-lab product this repository does not deploy)
    with ``until`` = ``switched_on`` + ``rollback_days``, the ledger row's window (ADR-0043, the
    one source of it), and the fields only a primary may carry move with primacy.  Pure: the
    clock is the caller's ``switched_on``.  Refused unless the result validates and leaves
    ``row`` the one primary of ``capability``."""
    from homelabnext.registry.model import standing_of

    _validate(dict(doc))  # the starting point must be valid too
    services = doc.get("services", {})
    cand = services.get(row)
    if cand is None:
        raise FlipError(f"no service {row!r} in the registry")
    if cand.get("capability") != capability:
        raise FlipError(
            f"{row} serves {cand.get('capability')!r}, not {capability!r}: promoting it would "
            f"leave {capability} with no primary"
        )
    tier = standing_of(cand)
    if tier != "eval":
        raise FlipError(
            f"{row} is {'the primary' if tier == 'primary' else 'a ' + tier + ' row'} of "
            f"{capability}: only an eval row is promoted (a rollback is the promotion's inverse)"
        )
    if (
        isinstance(rollback_days, bool)
        or not isinstance(rollback_days, int)
        or not 1 <= rollback_days <= MAX_ROLLBACK_DAYS
    ):
        raise FlipError(
            f"rollback_days is a whole number of days from 1 to {MAX_ROLLBACK_DAYS}, not "
            f"{rollback_days!r}"
        )
    day = _date(switched_on)
    until = (day + dt.timedelta(days=rollback_days)).isoformat()
    incumbent_tier = "legacy" if old_lab else "retiring"
    current = _primaries(doc, capability)
    incumbent = current[0] if current else None
    changes = [
        Change(
            f"services.{row}.standing",
            copy.deepcopy(cand.get("standing")),
            None,
            _before_key(cand, "standing"),
        )
    ]
    if incumbent is not None:
        inc = services[incumbent]
        reason = why or (
            f"replaced by {row} on {day.isoformat()}; "
            + (
                "the old lab holds it through the ledger's rollback window"
                if old_lab
                else "stopped and kept restorable for its rollback window"
            )
        )
        changes.append(
            Change(
                f"services.{incumbent}.standing",
                copy.deepcopy(inc.get("standing")),
                {"tier": incumbent_tier, "until": until, "why": reason},
            )
        )
        for fld in [k for k in inc if k in PRIMARY_ONLY]:  # document order: anchors stay valid
            if cand.get(fld) is not None:  # unreachable on a valid eval row; refused, not merged
                raise FlipError(
                    f"{row} already declares {fld}; it takes {incumbent}'s at the switch"
                )
            changes.append(
                Change(f"services.{incumbent}.{fld}", inc[fld], None, _before_key(inc, fld))
            )
            changes.append(Change(f"services.{row}.{fld}", None, inc[fld]))
        lowered = _lowered_ceiling(capability, inc, cand)
        if lowered is not None:
            changes.append(
                Change(f"services.{incumbent}.tlp_ceiling", inc.get("tlp_ceiling"), lowered)
            )
    elif old_lab:
        raise FlipError(f"{capability} has no primary: there is no old-lab incumbent to retire")
    plan = PromotePlan(
        capability,
        row,
        incumbent,
        incumbent_tier,
        day.isoformat(),
        rollback_days,
        until,
        tuple(changes),
    )
    plan.apply(doc)  # validates, and checks row is the capability's one primary
    return plan


def _flow(v: Any) -> str:
    """One-line flow YAML in the registry's style: a mapping's standing keys first, a date-like
    or awkward string double-quoted, anything else plain."""
    if isinstance(v, Mapping):
        keys = [k for k in _STANDING_ORDER if k in v] + sorted(
            k for k in v if k not in _STANDING_ORDER
        )
        return "{" + ", ".join(f"{k}: {_flow(v[k])}" for k in keys) + "}"
    if isinstance(v, str):
        plain = v == v.strip() and v != "" and not re.match(r"^[0-9]", v)
        if plain:
            try:
                plain = yaml.safe_load(f"{{k: {v}}}") == {"k": v}
            except yaml.YAMLError:
                plain = False
        return v if plain else json.dumps(v)
    return yaml.safe_dump(v, default_flow_style=True).split("\n")[0]


def _row_bounds(lines: list[str], service: str) -> tuple[int, int]:
    """The [start, end) line range of ``service``'s block under ``services:``: its key line to
    after its last field line (its fields indented four spaces, as ``flip_text`` reads them)."""
    in_services = False
    start = end = None
    for i, line in enumerate(lines):
        if re.match(r"^services:\s*(#.*)?$", line):
            in_services = True
            continue
        if not in_services or line.strip() == "" or line.lstrip().startswith("#"):
            continue
        m = _KEY.match(line)
        if not line.startswith(" ") or (start is not None and m and len(m.group("indent")) <= 2):
            if start is not None:
                break
            in_services = line.startswith(" ")
            continue
        if start is None:
            if m and len(m.group("indent")) == 2 and m.group("key") == service:
                start = i
            continue
        end = i + 1
    if start is None or end is None:
        raise FlipError(f"cannot find service {service!r} as a block of fields under services:")
    return start, end


def _field_bounds(lines: list[str], start: int, end: int, fld: str) -> tuple[int, int] | None:
    """The [first, last) lines of field ``fld`` (its key line and deeper continuation lines)."""
    for i in range(start + 1, end):
        m = _KEY.match(lines[i])
        if m and len(m.group("indent")) == 4 and m.group("key") == fld:
            j = i + 1
            while j < end and (
                lines[j].strip() == "" or len(lines[j]) - len(lines[j].lstrip()) > 4
            ):
                j += 1
            while j > i + 1 and lines[j - 1].strip() == "":
                j -= 1
            return i, j
    return None


def _edit_text(text: str, plan: PromotePlan) -> str:
    lines = text.split("\n")
    for c in plan.changes:
        _, name, fld = c.path.split(".")
        start, end = _row_bounds(lines, name)
        span = _field_bounds(lines, start, end, fld)
        new = [] if c.after is None else [f"    {fld}: {_flow(c.after)}"]
        if span is not None:
            lines[span[0] : span[1]] = new
            continue
        if c.before is not None:
            raise FlipError(f"cannot find {c.path} in the registry text")
        # a field that appears goes after the field it followed before it went, else last
        at = _field_bounds(lines, start, end, c.anchor) if c.anchor else None
        lines[at[1] if at else end : at[1] if at else end] = new
    return "\n".join(lines)


def promote_text(text: str, plan: PromotePlan) -> str:
    """Apply ``plan`` to registry YAML text, editing only the promoted rows' changed fields.

    A field that appears is written on one line at the end of its row; one that goes is removed
    with its continuation lines.  Refused unless the result parses to ``plan.apply`` of the text
    and the inverse plan restores the text byte for byte, so a rollback is always exact."""
    out = _edit_text(text, plan)
    if load_doc(out) != plan.apply(load_doc(text)):
        raise FlipError("text edit does not reproduce the planned document; refusing to write it")
    if _edit_text(out, plan.inverse()) != text:
        raise FlipError(
            f"the promotion of {plan.row} has no byte-exact inverse in this text: write each "
            "changed field on one line, at the end of its row, as the registry's own style does "
            '(standing: {tier: eval, until: "YYYY-MM-DD", why: ...})'
        )
    return out
