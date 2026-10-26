# SPDX-License-Identifier: Apache-2.0
"""``include:`` rules on a profile spec: which related knowledge goes into the context pack.

A rule is small and declarative::

    include:
      - from: capabilities          # seeds: capabilities | mcp | services | task
        only: [cap:lake-query]      # optional, capabilities/mcp only: a subset of the grants
        kinds: [runbook, lesson, check, schema, doc]
        depth: 1                    # hops from the seeds, 1..3
        budget: 12                  # max nodes this rule includes, 1..50
        max_chars: 4000             # per included node (the pack's section cap), 200..20000
        require_reviews: [agent_check, audit]   # optional, for lessons/runbooks/criteria
        detail: summary             # optional: full (default) | summary | outline

Seeds are always grants: ``capabilities`` are the profile's granted ``cap:`` ids, ``mcp`` its
granted MCP servers, ``services`` the registry services that provide a granted capability (found
in the graph at pack time), ``task`` the nodes :func:`homelabnext.graph.seeds_for` finds in the
task's paths and text (an ungranted capability, service or MCP server named there is dropped as a
seed, with the reason recorded).  :func:`normalise_include` refuses an ``only`` entry the profile
is not granted, and a rule that seeds from a grant set the profile does not hold
(:class:`~homelabnext.agent.errors.IncludeViolation`).  It is called by the compiler, by
:func:`~homelabnext.agent.compiler.verify_profile` and again when a pack is built, so a profile
edited after compiling (digest recomputed or not) cannot seed from an ungranted thing either.

``detail`` is how much of each included node the pack carries (ADR-0032's levels): ``full`` (the
default: the whole record or page, as before), ``summary`` (level 0: id, kind, title, path and the
summary, with where it came from) or ``outline`` (the summary and the heading outline with sizes,
so the agent can open one section through the MCP ``section`` tool).  Only a non-``full`` detail is
written to the normalised rule, so a profile that never names it keeps its digest.  A node several
rules include is carried at the richest detail any of them asks.  Grants, exclusions, ranking and
budgets do not depend on it.

Rules add knowledge; they never add a grant, a tool or a broker action.  The normalised form
writes every default, so the profile digest pins the whole rule.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .digest import canonical_json
from .errors import IncludeViolation, SpecError

INCLUDE_FROM = ("capabilities", "mcp", "services", "task")
KNOWLEDGE_KINDS = ("adr", "check", "doc", "inv", "lesson", "runbook", "schema")
REVIEW_TIERS = ("agent_check", "audit", "human")
DETAILS = ("full", "summary", "outline")  # least to most reading; `full` is the default
RULE_KEYS = frozenset(
    {"from", "only", "kinds", "depth", "budget", "max_chars", "require_reviews", "detail"}
)
DEFAULTS = {"depth": 1, "budget": 12, "max_chars": 4000}
LIMITS = {"depth": (1, 3), "budget": (1, 50), "max_chars": (200, 20000)}


def _int(rule: Mapping[str, Any], key: str, where: str) -> int:
    v = rule.get(key, DEFAULTS[key])
    lo, hi = LIMITS[key]
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise SpecError(f"{where}: {key} must be an integer in {lo}..{hi} (got {v!r})")
    return v


def _names(rule: Mapping[str, Any], key: str, allowed: tuple[str, ...], where: str) -> list[str]:
    v = rule.get(key)
    if not isinstance(v, list) or not v or not all(isinstance(x, str) for x in v):
        raise SpecError(f"{where}: {key} must be a non-empty list of {list(allowed)}")
    bad = sorted(set(v) - set(allowed))
    if bad:
        raise SpecError(f"{where}: {key}: unknown {bad} (allowed: {list(allowed)})")
    return sorted(set(v))


def normalise_include(raw: Any, grants: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The normalised rules (sorted, de-duplicated, defaults written) for a profile holding
    ``grants`` (``{capabilities: [cap:...], mcp: [slug, ...]}``).

    Raises :class:`SpecError` for a malformed rule and :class:`IncludeViolation`, listing every
    problem, for a rule that would seed from something not granted."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise SpecError("include must be a list of rules")
    caps = sorted(set(grants.get("capabilities") or ()))
    mcp = sorted(set(grants.get("mcp") or ()))
    held = {"capabilities": caps, "mcp": mcp, "services": caps}
    out: dict[str, dict[str, Any]] = {}
    violations: list[str] = []
    for n, rule in enumerate(raw):
        where = f"include[{n}]"
        if not isinstance(rule, Mapping):
            raise SpecError(f"{where}: a rule must be a mapping")
        extra = sorted(set(rule) - RULE_KEYS)
        if extra:
            raise SpecError(f"{where}: unknown keys {extra} (allowed: {sorted(RULE_KEYS)})")
        src = rule.get("from")
        if src not in INCLUDE_FROM:
            raise SpecError(f"{where}: from must be one of {list(INCLUDE_FROM)} (got {src!r})")
        norm: dict[str, Any] = {
            "from": src,
            "kinds": _names(rule, "kinds", KNOWLEDGE_KINDS, where),
            **{k: _int(rule, k, where) for k in ("depth", "budget", "max_chars")},
        }
        if "detail" in rule:
            detail = rule["detail"]
            if detail not in DETAILS:
                raise SpecError(f"{where}: detail must be one of {list(DETAILS)} (got {detail!r})")
            if detail != "full":  # the default is not written: existing digests stay as they are
                norm["detail"] = detail
        if "require_reviews" in rule:
            from homelabnext.reviews import normalize_role  # (reviews imports this package)

            tiers = rule["require_reviews"]
            if isinstance(tiers, list):  # the deprecated tier `challenge` reads as `audit`
                tiers = [normalize_role(t, f"{where}: require_reviews") for t in tiers]
            norm["require_reviews"] = _names(
                {"require_reviews": tiers}, "require_reviews", REVIEW_TIERS, where
            )
        if "only" in rule:
            if src not in ("capabilities", "mcp"):
                raise SpecError(f"{where}: only is allowed with from: capabilities or mcp")
            only = rule["only"]
            if not isinstance(only, list) or not only or not all(isinstance(x, str) for x in only):
                raise SpecError(f"{where}: only must be a non-empty list of names")
            ungranted = sorted(set(only) - set(held[src]))
            if ungranted:
                violations.append(f"{where}: only names {ungranted}, not in the granted {src}")
            norm["only"] = sorted(set(only))
        elif src in held and not held[src]:
            what = "capabilities" if src == "services" else src
            violations.append(f"{where}: from: {src} but the profile is granted no {what}")
        out.setdefault(canonical_json(norm), norm)
    if violations:
        raise IncludeViolation(violations)
    return [out[k] for k in sorted(out)]
