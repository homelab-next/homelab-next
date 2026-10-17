# SPDX-License-Identifier: Apache-2.0
"""Profile compiler: spec + parts library -> compiled, digested profile.

A *spec* says what an agent should be: a persona, skills, capabilities, a model role, the MCP
servers it wants, a tier, budgets and a permission **ceiling**.  The compiler harvests each named
part from a :class:`PartsLibrary` (keyed by logical id, resolved through
:mod:`homelabnext.ids`), refuses anything the ceiling does not allow, and emits a profile that
validates against ``schemas/agent/profile.schema.json``.

Rules, all enforced here and tested:

* a missing logical id is an error naming every missing id (never a silent skip);
* grants are a subset of the ceiling: MCP servers, capabilities, tier rank, and each budget;
* the output is deterministic: lists are sorted and de-duplicated, and the digest is the
  sha256 of the canonical JSON of the profile without its own ``digest`` field;
* every harvested part is recorded in ``provenance`` with the digest of its content.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext.ids import IdError, Resolver, UnresolvedId, parse

from .digest import digest_of, sha256_text
from .errors import BudgetError, CeilingViolation, MissingPartError, SpecError
from .schemas import schema_errors

TIER_RANK = {"read": 0, "write": 1, "execute": 2, "privileged": 3}
BUDGET_KEYS = ("max_input_tokens", "max_output_tokens", "max_runtime_s", "max_tool_calls")


@dataclass(frozen=True)
class Part:
    """One harvested part: its logical id, adapter locator and content digest."""

    id: str
    locator: str
    content: str
    digest: str


class PartsLibrary:
    """Parts keyed by logical id.

    ``resolver`` maps a logical id to an adapter locator (a relative path, a URI, anything the
    ``reader`` understands); ``reader(locator) -> str`` returns the content.  Tests and examples
    use :class:`homelabnext.ids.MappingResolver` with an in-memory ``reader``.
    """

    def __init__(
        self, resolver: Resolver, reader: Callable[[str], str], source: str = "parts-library"
    ) -> None:
        self.resolver = resolver
        self.reader = reader
        self.source = source

    def get(self, logical_id: str) -> Part:
        locator = self.resolver.resolve(logical_id)  # raises UnresolvedId
        content = self.reader(locator)
        return Part(logical_id, locator, content, sha256_text(content))

    def has(self, logical_id: str) -> bool:
        try:
            self.resolver.resolve(logical_id)
        except UnresolvedId:
            return False
        return True


def check_ceiling(grants: Mapping[str, Any], ceiling: Mapping[str, Any]) -> list[str]:
    """Every way ``grants`` exceeds ``ceiling`` (empty list = within the ceiling).

    ``grants`` has ``mcp``, ``capabilities``, ``tier``; ``ceiling`` the same plus optional
    ``budgets`` (checked by :func:`check_budgets`, not here).
    """
    problems: list[str] = []
    for key in ("mcp", "capabilities"):
        extra = sorted(set(grants.get(key, ())) - set(ceiling.get(key, ())))
        if extra:
            problems.append(f"{key} outside ceiling: {extra}")
    g, c = grants.get("tier"), ceiling.get("tier")
    if g not in TIER_RANK or c not in TIER_RANK:
        problems.append(f"tier must be one of {sorted(TIER_RANK)} (got grant {g!r}, ceiling {c!r})")
    elif TIER_RANK[g] > TIER_RANK[c]:
        problems.append(f"tier {g!r} is above the ceiling tier {c!r}")
    return problems


def check_budgets(budgets: Any, cap: Mapping[str, Any] | None = None) -> list[str]:
    if not isinstance(budgets, Mapping):
        return ["budgets must be a mapping with " + ", ".join(BUDGET_KEYS)]
    problems = []
    for k in BUDGET_KEYS:
        v = budgets.get(k)
        floor = 0 if k == "max_tool_calls" else 1
        if not isinstance(v, int) or isinstance(v, bool) or v < floor:
            problems.append(f"budgets.{k} must be an integer >= {floor}")
        elif cap and k in cap and v > cap[k]:
            problems.append(f"budgets.{k}={v} exceeds the ceiling budget {cap[k]}")
    return problems


def _ids(spec: Mapping[str, Any], key: str, kind: str) -> list[str]:
    raw = spec.get(key, [])
    if not isinstance(raw, list):
        raise SpecError(f"{key}: must be a list of {kind}: ids")
    out = []
    for item in raw:
        try:
            lid = parse(item)
        except IdError as exc:
            raise SpecError(f"{key}: {exc}") from None
        if lid.kind != kind:
            raise SpecError(f"{key}: {item!r} is a {lid.kind}: id, expected {kind}:")
        out.append(str(lid))
    return sorted(set(out))


def compile_profile(spec: Mapping[str, Any], library: PartsLibrary) -> dict[str, Any]:
    """Compile ``spec`` into a profile dict.  Pure given the library; raises
    :class:`~homelabnext.agent.errors.AgentError` subclasses, never returns a partial profile."""
    if not isinstance(spec, Mapping):
        raise SpecError("spec must be a mapping")
    for key in ("id", "persona", "model_role", "tier", "ceiling", "budgets", "data_tier"):
        if key not in spec:
            raise SpecError(f"spec is missing required key {key!r}")
    pid = _ids({"id": [spec["id"]]}, "id", "profile")[0]
    persona = _ids({"persona": [spec["persona"]]}, "persona", "persona")[0]
    model_role = _ids({"model_role": [spec["model_role"]]}, "model_role", "mdl")[0]
    skills = _ids(spec, "skills", "skill")
    caps = _ids(spec, "capabilities", "cap")
    mcp = sorted(set(spec.get("mcp", [])))

    # 1. harvest: every logical id must be in the library, reported together
    wanted = [persona, *skills, *caps]
    missing = [i for i in wanted if not library.has(i)]
    if missing:
        raise MissingPartError(missing)
    parts = [library.get(i) for i in wanted]

    # 2. ceiling: a profile can never grant more than its ceiling
    ceiling_in = spec["ceiling"]
    if not isinstance(ceiling_in, Mapping):
        raise SpecError("ceiling must be a mapping")
    ceiling: dict[str, Any] = {
        "mcp": sorted(set(ceiling_in.get("mcp", []))),
        "capabilities": _ids(ceiling_in, "capabilities", "cap"),
        "tier": ceiling_in.get("tier"),
    }
    if "budgets" in ceiling_in:
        ceiling["budgets"] = dict(ceiling_in["budgets"])
    grants = {"mcp": mcp, "capabilities": caps, "tier": spec["tier"]}
    violations = check_ceiling(grants, ceiling)
    if violations:
        raise CeilingViolation(violations)

    # 3. budgets
    bproblems = check_budgets(spec["budgets"], ceiling.get("budgets"))
    if bproblems:
        raise BudgetError("; ".join(bproblems))

    profile: dict[str, Any] = {
        "id": pid,
        "persona": persona,
        "model_role": model_role,
        "parts": {"skills": skills, "capabilities": caps},
        "grants": grants,
        "ceiling": ceiling,
        "memory_scopes": sorted(set(spec.get("memory_scopes", []))),
        "data_tier": spec["data_tier"],
        "budgets": {k: spec["budgets"][k] for k in BUDGET_KEYS},
        "budget_mode": spec.get("budget_mode", "warn"),
    }
    # the spec entry digests the *normalised* spec, so list order in the source file is irrelevant
    provenance = sorted(
        ({"id": p.id, "source": library.source, "digest": p.digest} for p in parts),
        key=lambda e: e["id"],
    )
    provenance.append({"id": pid, "source": "spec", "digest": digest_of(profile)})
    profile["provenance"] = provenance
    profile["digest"] = digest_of(profile)
    errs = schema_errors("agent", "profile", profile)
    if errs:
        raise SpecError("compiled profile fails its schema: " + "; ".join(errs))
    return profile


def profile_digest(profile: Mapping[str, Any]) -> str:
    """Recompute a profile's digest (everything except ``digest`` itself)."""
    return digest_of({k: v for k, v in profile.items() if k != "digest"})


def verify_profile(profile: Mapping[str, Any]) -> list[str]:
    """Problems with an already compiled profile: schema, ceiling, budgets, digest."""
    problems = schema_errors("agent", "profile", profile)
    if problems:
        return problems
    problems += check_ceiling(profile["grants"], profile["ceiling"])
    problems += check_budgets(profile["budgets"], profile["ceiling"].get("budgets"))
    if profile_digest(profile) != profile["digest"]:
        problems.append("digest does not match the profile content (edited after compile?)")
    return problems


def _plain(obj: Any) -> Any:
    """JSON-plain copy (Mapping -> dict, tuple -> list) so digests are stable across loaders."""
    if isinstance(obj, Mapping):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_plain(v) for v in obj]
    return obj
