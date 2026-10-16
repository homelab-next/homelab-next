# SPDX-License-Identifier: Apache-2.0
"""The cutover flip: retarget one service's endpoint alias inside a registry document.

Consumers resolve ``<capability>.<svc_label>.<domain>``; the registry row behind that alias says
which host, port and implementation answer. Cutover is therefore one reviewed change to that row
(ADR-0002, ADR-0005), and rollback is the same change reversed.

:func:`plan_flip` is a pure function on a parsed registry document. It validates the result with
the registry's own rules and returns a :class:`FlipPlan` carrying the diff and its exact
:meth:`~FlipPlan.inverse`. :func:`flip_text` applies a plan to the YAML *text*, touching only the
changed scalar lines (comments and layout survive) and proving the result equals the plan.
"""

from __future__ import annotations

import copy
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
        out = copy.deepcopy(dict(doc))
        for c in self.changes:
            _, name, field = c.path.split(".")
            try:
                row = out["services"][name]
            except KeyError:
                raise FlipError(f"no service {name!r} in the registry") from None
            if row.get(field) != c.before:
                raise FlipError(
                    f"{c.path} is {row.get(field)!r}, the plan expects {c.before!r}; "
                    "the registry changed since the plan was made"
                )
            row[field] = c.after
        _validate(out)
        return out

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
