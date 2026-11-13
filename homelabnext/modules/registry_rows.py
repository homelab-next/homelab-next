# SPDX-License-Identifier: Apache-2.0
"""Registry equality: each selected module's contributed service rows appear, identically, in the
lab's registry (``lab/services.yml``; docs/modules/selection.md, "Registry rows: checked, not
generated").

The operator chose to keep the lab registry hand-written and to *check* it against the modules
rather than generate it from the selection.  So the registry stays the one file every generator
reads, and this check is what keeps it from drifting from the modules it claims to run.

A contributed row is what the module ships (``contributes.services``); the row the lab registry
must carry is that row **as bound by the site** (:func:`expected_rows`):

* a provider's row is keyed by its slot and is renamed to each instance the site selects of that
  provider for that slot; its ``version`` is the provider's ``product.version`` (a provider's row
  never repeats it);
* a feature's or core module's row keeps its name;
* ``host`` names one of the module's host roles; the site's placement maps it to a site host, and
  that host's registry name is its guest's name (``hosts.<name>.guest: guest:<id>``, the guest
  registry fragment's own key) or, for a stand-in host, the site host's name.

:func:`row_problems` then names every difference, field by field: a row the registry lacks, a
field whose value differs, a field one side has and the other does not.  The fields in
:data:`SITE_FIELDS` are the lab's own facts about a row (a generic module cannot know them) and are
compared only when the module's row sets them.  A host role the site does not place is a problem
of its own (the registry's ``host`` cannot be judged), and the other fields are still compared.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

Doc = dict[str, Any]

__all__ = ["SITE_FIELDS", "Expected", "expected_rows", "row_problems"]

#: the fields of a registry row that are the lab's, not the module's: compared only when the
#: module's row sets them.  ``standing`` (ADR-0039: whether this row is the capability's primary,
#: an eval, retiring or legacy, with its ``until`` and ``why``), ``backup_job`` (the lab's backup
#: schedule) and ``scope`` (the writer-tool scope, which only narrows what agents file about the
#: service).  Never ``clients``: extra zones widen who may reach the service (firewall edges, the
#: agent access map), so a registry that adds them differs from the module, and the module must
#: say so too
SITE_FIELDS = frozenset({"standing", "backup_job", "scope"})

#: the longest value a problem prints before it is cut (a row's field can be a large mapping)
SHOWN = 120


@dataclass(frozen=True)
class Expected:
    """One row the lab registry must carry: its registry ``name``, the ``module`` that
    contributes it (``instance`` for a provider's), the module's own row name ``source`` and the
    ``row`` as the site binds it.  ``unplaced`` names the host role when the site places it on no
    host (``row['host']`` is then the role, which no registry host is)."""

    name: str
    module: str
    instance: str | None
    source: str
    row: Doc
    unplaced: str | None = None

    @property
    def who(self) -> str:
        if self.instance is None or self.instance == self.module:
            return self.module
        return f"{self.module} (instance {self.instance})"


def _registry_host(site: Doc, host: str) -> str:
    """The registry's name for site host ``host``: its guest's name, or the site host's own."""
    hosts = site.get("hosts")
    h = hosts.get(host) if isinstance(hosts, Mapping) else None
    ref = h.get("guest") if isinstance(h, Mapping) else None
    if isinstance(ref, str) and ref.startswith("guest:"):
        return ref.removeprefix("guest:")
    return host


def _bind(
    site: Doc, row: Doc, placement: Mapping[str, Any], version: str | None
) -> tuple[Doc, str | None]:
    out = dict(row)
    if version is not None:
        out["version"] = version
    role = row.get("host")
    target = (
        placement.get(role) if isinstance(placement, Mapping) and isinstance(role, str) else None
    )
    if isinstance(target, str):
        out["host"] = _registry_host(site, target)
        return out, None
    return out, str(role)


def expected_rows(
    site: Doc, sel: Mapping[str, Doc], rows: Mapping[str, Mapping[str, Doc]]
) -> Iterator[Expected]:
    """Every row the lab registry must carry for the selection: ``sel`` the selected modules
    (:func:`homelabnext.modules.rules.selected`), ``rows`` each module's contributed rows by row
    name (the loader's ``Inputs.rows``)."""
    for slot, lines in sorted((site.get("slots") or {}).items()):
        if not isinstance(lines, list):
            continue  # none or pass-through: nothing is contributed
        for line in lines:
            if not isinstance(line, Mapping):
                continue  # the selection schema refuses it
            mid, inst = line.get("provider"), line.get("instance")
            m = sel.get(mid) if isinstance(mid, str) else None
            if not isinstance(m, Mapping) or not isinstance(inst, str):
                continue  # the site rules report it
            row = rows.get(mid, {}).get(slot)
            if not isinstance(row, Mapping):
                continue  # this provider contributes no row for the slot
            product = m.get("product")
            version = str(product.get("version")) if isinstance(product, Mapping) else None
            bound, unplaced = _bind(site, dict(row), line.get("placement") or {}, version)
            yield Expected(inst, mid, inst, slot, bound, unplaced)
    for section in ("features", "core"):
        for mid, entry in sorted((site.get(section) or {}).items()):
            if mid not in sel:
                continue
            placement = (entry.get("placement") or {}) if isinstance(entry, Mapping) else {}
            for name, row in sorted(rows.get(mid, {}).items()):
                if isinstance(row, Mapping):
                    bound, unplaced = _bind(site, dict(row), placement, None)
                    yield Expected(name, mid, None, name, bound, unplaced)
    # a core module is selected on every site, placed or not
    for mid in sorted(sel):
        if (
            isinstance(sel[mid], Mapping)
            and sel[mid].get("kind") == "core"
            and mid not in (site.get("core") or {})
        ):
            for name, row in sorted(rows.get(mid, {}).items()):
                if isinstance(row, Mapping):
                    bound, unplaced = _bind(site, dict(row), {}, None)
                    yield Expected(name, mid, None, name, bound, unplaced)


def _shown(value: Any) -> str:
    """A value as a problem prints it: JSON with sorted keys (every control character escaped,
    so a planted value cannot carry a line break or a terminal escape), cut at :data:`SHOWN`."""
    if value is _ABSENT:
        return "(absent)"
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    except (TypeError, ValueError, RecursionError):
        text = repr(type(value).__name__)
    return text if len(text) <= SHOWN else text[: SHOWN - 3] + "..."


def _name(text: str) -> str:
    s = str(text)
    plain = s and s.isascii() and all(c.isalnum() or c in "-_." for c in s)
    return s if plain else json.dumps(s, ensure_ascii=True)


_ABSENT = object()


def _same(field: str, a: Any, b: Any) -> bool:
    if field == "version" and a is not _ABSENT and b is not _ABSENT:
        return str(a) == str(b)  # an unquoted YAML version reads as a number
    return a == b


def row_problems(
    site: Doc, sel: Mapping[str, Doc], rows: Mapping[str, Mapping[str, Doc]], registry: Any
) -> list[str]:
    """A problem for every difference between the rows the selection's modules contribute (as
    the site binds them, :func:`expected_rows`) and the lab registry's ``services``."""
    services = registry.get("services") if isinstance(registry, Mapping) else None
    if not isinstance(services, Mapping):
        return ["the lab registry has no services mapping: no contributed row could be compared"]
    out: list[str] = []
    for e in expected_rows(site, sel, rows):
        where = f"services.{_name(e.name)}"
        src = "" if e.source == e.name else f" (its row {_name(e.source)})"
        if e.unplaced is not None:
            out.append(
                f"{where}: {e.who}'s host role {_name(e.unplaced)} is placed on no site host, "
                "so the registry row's host cannot be compared"
            )
        have = services.get(e.name)
        if not isinstance(have, Mapping):
            out.append(
                f"{where}: {e.who} contributes this row{src}, but the lab registry has no such "
                "row (copy it as the site binds it)"
            )
            continue
        for field in sorted({*e.row, *have}, key=str):
            if field == "host" and e.unplaced is not None:
                continue
            if field in SITE_FIELDS and field not in e.row:
                continue
            want, got = e.row.get(field, _ABSENT), have.get(field, _ABSENT)
            if not _same(field, want, got):
                out.append(
                    f"{where}.{_name(field)}: {e.who} contributes {_shown(want)}{src}, "
                    f"the lab registry has {_shown(got)}"
                )
    return out
