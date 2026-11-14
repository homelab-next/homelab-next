# SPDX-License-Identifier: Apache-2.0
"""``provider_for(slot, instance)``: which module serves a slot instance on a site (ADR-0027
decision 9; docs/modules.md, "Site selection").

The site selection (``platform/module_selection``) is the one answer: a consumer resolves a slot
from it, never from a product name.  :func:`provider_for` reads it; :func:`providers` lists every
selected slot instance with its provider's product and licence (``hnx modules providers``); and
:func:`registry_impl_problems` compares the core registry's ``impl:`` with the selection, so a
registry that still names the product a swap replaced is a problem rather than a second answer.
The registry and the baselines are not generated from the selection here: that stays an
operator decision (ADR-0027, Consequences).  All functions assume schema-valid documents.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "Provider",
    "ProviderLookupError",
    "licence_text",
    "provider_for",
    "providers",
    "registry_impl_problems",
]

Doc = dict[str, Any]


class ProviderLookupError(LookupError):
    """The selection cannot answer: no such slot, no such instance, or several and none named."""


@dataclass(frozen=True)
class Provider:
    """One selected slot instance and what serves it."""

    slot: str
    instance: str
    module: str
    product: str
    version: str
    aliases: tuple[str, ...]
    licence_kind: str
    licence_spdx: str | None

    @property
    def licence(self) -> str:
        return licence_text(self.licence_kind, self.licence_spdx)


def licence_text(kind: str, spdx: str | None) -> str:
    """``open-source Apache-2.0``, or the kind alone when the licence has no SPDX id."""
    return f"{kind} {spdx}" if spdx else kind


def _provider(slot: str, line: Doc, mods: dict[str, Doc]) -> Provider:
    mid = line["provider"]
    if mid not in mods:
        raise ProviderLookupError(f"{slot}/{line['instance']}: {mid} has no manifest")
    m = mods[mid]
    product, licence = m.get("product", {}), m.get("licence", {})
    return Provider(
        slot=slot,
        instance=line["instance"],
        module=mid,
        product=product.get("name", ""),
        version=product.get("version", ""),
        aliases=tuple(product.get("aliases", [])),
        licence_kind=licence.get("kind", ""),
        licence_spdx=licence.get("spdx"),
    )


def provider_for(
    site: Doc, mods: dict[str, Doc], slot: str, instance: str | None = None
) -> Provider | None:
    """The provider serving ``slot`` (``cap:`` optional) on the site, at ``instance``.

    ``None`` when the site selects ``none`` or ``pass-through`` for the slot (nothing serves it,
    by decision).  Without ``instance`` the slot must have exactly one selected instance.  A slot
    the selection does not name, a slot served outside modules (an incumbent: the registry row
    answers, not a module), a planned slot (not served yet), an instance it does not select, and
    an ambiguous lookup raise
    :class:`ProviderLookupError`: a consumer never guesses."""
    slot = slot.removeprefix("cap:")
    lines = site.get("slots", {}).get(slot)
    if lines is None:
        inc = (site.get("incumbents") or {}).get(slot)
        if isinstance(inc, dict):
            raise ProviderLookupError(
                f"{slot}: served outside modules by registry row {inc.get('service')} (an "
                "incumbent): no module provides it"
            )
        plan = (site.get("planned") or {}).get(slot)
        if isinstance(plan, dict):
            raise ProviderLookupError(
                f"{slot}: planned, not served yet ({plan.get('why')}; review by "
                f"{plan.get('review_by')}): nothing provides it"
            )
        raise ProviderLookupError(f"{slot}: the site selection does not name this slot")
    if not isinstance(lines, list):
        return None
    if instance is None:
        if len(lines) != 1:
            names = sorted(c["instance"] for c in lines)
            raise ProviderLookupError(f"{slot}: several instances are selected ({names}); name one")
        return _provider(slot, lines[0], mods)
    for c in lines:
        if c["instance"] == instance:
            return _provider(slot, c, mods)
    raise ProviderLookupError(f"{slot}/{instance}: the site selects no such instance")


def providers(site: Doc, mods: dict[str, Doc]) -> list[Provider]:
    """Every selected slot instance with its provider, sorted by slot and instance."""
    out = [
        _provider(slot, c, mods)
        for slot, lines in site.get("slots", {}).items()
        if isinstance(lines, list)
        for c in lines
    ]
    return sorted(out, key=lambda p: (p.slot, p.instance))


def registry_impl_problems(site: Doc, mods: dict[str, Doc], registry: Doc) -> list[str]:
    """A problem for each core registry row whose ``impl:`` is not the product (or an alias) of a
    provider the site selects for the row's ``capability``, and for each row of a capability the
    site selects ``none`` or ``pass-through`` for.  A row whose capability is not a slot of the
    selection is not judged."""
    selected = site.get("slots", {})
    out = []
    for name, row in sorted((registry.get("services") or {}).items(), key=lambda kv: str(kv[0])):
        if not isinstance(row, dict):
            continue  # the registry's own validation reports it
        cap = str(row.get("capability", "")).removeprefix("cap:")
        if cap not in selected:
            continue
        impl = row.get("impl", "")
        lines = selected[cap]
        if not isinstance(lines, list):
            out.append(
                f"services.{name}: capability {cap} is {lines} in the site selection, but the "
                f"registry still runs impl {impl!r}"
            )
            continue
        known = [_provider(cap, c, mods) for c in lines if c["provider"] in mods]
        if not any(impl == p.product or impl in p.aliases for p in known):
            want = sorted({p.product for p in known})
            out.append(
                f"services.{name}: impl {impl!r} is not the product of a provider the site "
                f"selects for {cap} ({', '.join(want) or 'none with a manifest'}): "
                "the selection is the one answer (provider_for)"
            )
    return out
