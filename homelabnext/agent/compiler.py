# SPDX-License-Identifier: Apache-2.0
"""Profile compiler: spec + parts library -> compiled, digested profile.

A *spec* says what an agent should be: a persona, skills, capabilities, a model role, the MCP
servers it wants, a tier and budgets.  The compiler harvests each named part from a
:class:`PartsLibrary` (keyed by logical id, resolved through :mod:`homelabnext.ids`), refuses
anything the permission **ceiling** does not allow, and emits a profile that validates against
``schemas/agent/profile.schema.json``.

Where the ceiling comes from matters.  A ceiling written in the spec it bounds is only a
statement of intent: whoever edits the spec can raise it.  The ceiling that limits a profile is
therefore read from a :class:`CeilingPolicy`, a separate file keyed by profile id that a
different owner reviews (``compile_profile(..., policy=)``, ``hnx agent compile --policy``).  A
spec may still carry a ``ceiling``; with a policy it may only narrow the policy's.  Without a
policy the spec's own ceiling is used and the result is self-consistent, nothing more.

:func:`verify_profile` checks a compiled profile against the policy (not against the ceiling
copied into the profile) and, given a lock (``{profile id: digest}``, reviewed and committed
next to the policy), that the profile is the one that was reviewed.

Rules, all enforced here and tested:

* a missing logical id is an error naming every missing id (never a silent skip);
* grants are a subset of the ceiling: MCP servers, capabilities, tier rank, and each budget;
* the output is deterministic: lists are sorted and de-duplicated, and the digest is the
  sha256 of the canonical JSON of the profile without its own ``digest`` field;
* every harvested part is recorded in ``provenance`` with the digest of its content;
* readers cannot act: a profile that reads untrusted content (``reads_untrusted``, true unless the
  spec says ``false``, and forced true by a policy entry that says so) may hold no grant whose
  capability class is shell/exec, file-write, egress or credential, nor an unclassified one
  (:mod:`homelabnext.agent.readers`).  The compiler refuses it whatever the ceiling allows, and
  :func:`verify_profile` refuses a compiled profile edited into that state;
* ``include:`` rules (:mod:`homelabnext.agent.include`) say which related knowledge goes into the
  pack; they may seed only from grants the profile holds (:class:`IncludeViolation`) and never
  add one.  A spec without ``include`` compiles to a profile without it;
* actors act only through the broker (:func:`homelabnext.agent.readers.broker_problems`, every
  profile, ADR-0030): an acting MCP server must be ``acts_via: broker`` in its catalog record (or
  a reviewed ``acts_via: direct`` one the policy's ``direct_mcp`` names for the profile), no
  acting capability but ``cap:broker``, and an acting tier only with ``cap:broker``
  (:class:`BrokerViolation`).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext.ids import IdError, Resolver, UnresolvedId, parse

from .digest import digest_of, sha256_text
from .errors import (
    AgentError,
    BrokerViolation,
    BudgetError,
    CatalogViolation,
    CeilingViolation,
    MissingPartError,
    ReaderViolation,
    SpecError,
)
from .include import normalise_include
from .readers import (
    DATA_TIERS,
    ToolClasses,
    broker_problems,
    default_classes,
    grant_problems,
    profile_problems,
    reader_problems,
)
from .schemas import schema_errors

TIER_RANK = {"read": 0, "write": 1, "execute": 2, "privileged": 3}
BUDGET_KEYS = ("max_input_tokens", "max_output_tokens", "max_runtime_s", "max_tool_calls")
#: an MCP catalog id (``schemas/platform/mcp_server.schema.json`` ``slug``)
_SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")


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


class CeilingPolicy:
    """Ceilings keyed by profile id, owned and reviewed separately from the profile specs.

    File shape (YAML or JSON)::

        ceilings:
          profile:reader: {mcp: [lake], capabilities: [cap:lake-query], tier: read,
                           budgets: {max_runtime_s: 900, ...}, reads_untrusted: true}

    ``reads_untrusted: true`` on an entry makes that profile a reader whatever its spec says
    (the policy owner, not the spec author, decides); ``false`` or absent leaves it to the spec.

    ``data_tier`` and ``model_role`` on an entry are what the policy owner attests for the
    profile: a profile (spec, compiled or lean) must say the same, and a profile may be granted
    a ``local-only`` MCP server only when its entry attests ``data_tier: local-only``, so a spec
    cannot declare itself local-only to receive local-only data (:meth:`attestation_problems`).
    A local-only profile is granted no MCP server that reaches the internet (a hosted server, or
    ``egress: internet``: its context would leave the lab) unless its entry names that server in
    ``internet_mcp``, an exception per profile and server that the policy owner makes.

    ``direct_mcp`` on an entry names the ``acts_via: direct`` MCP servers (an acting server that
    does not go through the broker, ADR-0030) the profile may hold: an exception per profile and
    server that the policy owner makes, on top of the record's ``direct_reason`` and human
    approve review (:func:`homelabnext.agent.readers.broker_problems`).  Without an entry the
    profile holds none.
    """

    def __init__(self, ceilings: Mapping[str, Mapping[str, Any]], source: str = "policy") -> None:
        if not isinstance(ceilings, Mapping) or not ceilings:
            raise SpecError(f"{source}: expected a non-empty 'ceilings' mapping of profile id")
        self.source = source
        self._readers = set()
        self._attested: dict[str, dict[str, str]] = {}
        self._internet: dict[str, frozenset[str]] = {}
        self._direct: dict[str, frozenset[str]] = {}
        for pid, c in ceilings.items():
            flag = c.get("reads_untrusted") if isinstance(c, Mapping) else None
            if flag is not None and not isinstance(flag, bool):
                raise SpecError(f"{source}: {pid}: reads_untrusted must be true or false")
            if flag:
                self._readers.add(_ids({"id": [pid]}, "id", "profile")[0])
            if not isinstance(c, Mapping):
                continue
            att: dict[str, str] = {}
            if c.get("data_tier") is not None:
                if c["data_tier"] not in DATA_TIERS:
                    raise SpecError(f"{source}: {pid}: data_tier must be one of {list(DATA_TIERS)}")
                att["data_tier"] = c["data_tier"]
            if c.get("model_role") is not None:
                att["model_role"] = _ids({"model_role": [c["model_role"]]}, "model_role", "mdl")[0]
            if att:
                self._attested[_ids({"id": [pid]}, "id", "profile")[0]] = att
            if c.get("internet_mcp") is not None:
                names = c["internet_mcp"]
                if not isinstance(names, list) or not all(
                    isinstance(n, str) and _SLUG.fullmatch(n) for n in names
                ):
                    raise SpecError(f"{source}: {pid}: internet_mcp is a list of MCP server ids")
                self._internet[_ids({"id": [pid]}, "id", "profile")[0]] = frozenset(names)
            if c.get("direct_mcp") is not None:
                names = c["direct_mcp"]
                if not isinstance(names, list) or not all(
                    isinstance(n, str) and _SLUG.fullmatch(n) for n in names
                ):
                    raise SpecError(f"{source}: {pid}: direct_mcp is a list of MCP server ids")
                self._direct[_ids({"id": [pid]}, "id", "profile")[0]] = frozenset(names)
        self._ceilings = {
            _ids({"id": [pid]}, "id", "profile")[0]: _normal_ceiling(c, f"{source}: {pid}")
            for pid, c in ceilings.items()
        }

    @classmethod
    def from_mapping(cls, doc: Mapping[str, Any], source: str = "policy") -> CeilingPolicy:
        if not isinstance(doc, Mapping):
            raise SpecError(f"{source}: expected a mapping with 'ceilings'")
        return cls(doc.get("ceilings"), source)

    def ceiling(self, profile_id: str) -> dict[str, Any]:
        if profile_id not in self._ceilings:
            raise CeilingViolation([f"{self.source} has no ceiling for {profile_id}"])
        return dict(self._ceilings[profile_id])

    def direct_mcp(self, profile_id: str) -> frozenset[str]:
        """The ``acts_via: direct`` MCP servers this policy lets ``profile_id`` hold (ADR-0030);
        empty for a profile it has no entry or no ``direct_mcp`` for."""
        return self._direct.get(profile_id, frozenset())

    def requires_reader(self, profile_id: str) -> bool:
        """True when the policy marks ``profile_id`` as reading untrusted content."""
        return profile_id in self._readers

    def attestation_problems(
        self,
        profile_id: str,
        data_tier: Any,
        model_role: Any,
        mcp: Iterable[str] = (),
        classes: ToolClasses | None = None,
    ) -> list[str]:
        """Where a profile's ``data_tier``/``model_role`` disagree with what this policy attests
        for it, a ``local-only`` MCP server granted without the policy attesting
        ``data_tier: local-only`` (a profile cannot vouch for itself), and a local-only profile
        (attested, or declared when the policy attests no tier) granted a server that reaches
        the internet which its entry's ``internet_mcp`` does not name."""
        att = self._attested.get(profile_id, {})
        out = []
        for key, value in (("data_tier", data_tier), ("model_role", model_role)):
            if key in att and value != att[key]:
                out.append(
                    f"{self.source} attests {key} {att[key]} for {profile_id}; the profile says "
                    f"{value}"
                )
        meta = (classes if classes is not None else default_classes()).catalog or {}
        if att.get("data_tier") != "local-only":
            local = sorted(n for n in mcp if (meta.get(n) or {}).get("data_tier") == "local-only")
            if local:
                out.append(
                    f"{profile_id} is granted local-only MCP server(s) {local}, but "
                    f"{self.source} does not attest data_tier: local-only for it (a profile "
                    "cannot declare itself local-only to receive local-only data)"
                )
        if att.get("data_tier", data_tier) == "local-only":
            allowed = self._internet.get(profile_id, frozenset())
            out_ = sorted(
                n for n in mcp if (meta.get(n) or {}).get("internet") and n not in allowed
            )
            if out_:
                out.append(
                    f"{profile_id} is local-only but is granted MCP server(s) {out_} that "
                    "reach the internet (a hosted server, or egress: internet), where its "
                    f"local-only context would go; {self.source} names none of them in its "
                    "internet_mcp for this profile (a named exception the policy owner makes)"
                )
        return out


def _normal_ceiling(c: Any, where: str) -> dict[str, Any]:
    if not isinstance(c, Mapping):
        raise SpecError(f"{where}: ceiling must be a mapping")
    out: dict[str, Any] = {
        "mcp": sorted(set(c.get("mcp", []))),
        "capabilities": _ids(c, "capabilities", "cap"),
        "tier": c.get("tier"),
    }
    if "budgets" in c:
        out["budgets"] = dict(c["budgets"])
    return out


def _ceiling_excess(inner: Mapping[str, Any], outer: Mapping[str, Any]) -> list[str]:
    """Ways ``inner`` (a ceiling) is wider than ``outer``."""
    out = [f"ceiling wider than the policy: {p}" for p in check_ceiling(inner, outer)]
    ib, ob = inner.get("budgets") or {}, outer.get("budgets") or {}
    for k in BUDGET_KEYS:
        if k in ob and (k not in ib or not isinstance(ib[k], int) or ib[k] > ob[k]):
            out.append(f"ceiling wider than the policy: budgets.{k} is not within {ob[k]}")
    return out


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


def compile_profile(
    spec: Mapping[str, Any],
    library: PartsLibrary,
    *,
    policy: CeilingPolicy | None = None,
    classes: ToolClasses | None = None,
) -> dict[str, Any]:
    """Compile ``spec`` into a profile dict.  Pure given the library; raises
    :class:`~homelabnext.agent.errors.AgentError` subclasses, never returns a partial profile.

    With ``policy`` the ceiling is the policy's entry for the profile id (a spec ceiling may only
    narrow it); without, it is the spec's own ``ceiling``.  ``classes`` is the capability-class
    table for the reader rule (default: the packaged ``tool_classes.yml``).
    """
    if not isinstance(spec, Mapping):
        raise SpecError("spec must be a mapping")
    required = ("id", "persona", "model_role", "tier", "budgets", "data_tier")
    for key in (*required, *(() if policy else ("ceiling",))):
        if key not in spec:
            raise SpecError(f"spec is missing required key {key!r}")
    pid = _ids({"id": [spec["id"]]}, "id", "profile")[0]
    persona = _ids({"persona": [spec["persona"]]}, "persona", "persona")[0]
    model_role = _ids({"model_role": [spec["model_role"]]}, "model_role", "mdl")[0]
    skills = _ids(spec, "skills", "skill")
    caps = _ids(spec, "capabilities", "cap")
    mcp = sorted(set(spec.get("mcp", [])))
    reads = spec.get("reads_untrusted", True)  # fail closed: an actor must say false
    if not isinstance(reads, bool):
        raise SpecError("reads_untrusted must be true or false")

    # 1. harvest: every logical id must be in the library, reported together
    wanted = [persona, *skills, *caps]
    missing = [i for i in wanted if not library.has(i)]
    if missing:
        raise MissingPartError(missing)
    parts = [library.get(i) for i in wanted]

    grants = {"mcp": mcp, "capabilities": caps, "tier": spec["tier"]}

    # 2. ceiling: a profile can never grant more than its ceiling
    own = _normal_ceiling(spec["ceiling"], "spec") if "ceiling" in spec else None
    violations: list[str] = []
    if policy is not None:
        ceiling = policy.ceiling(pid)
        if own is not None:
            violations += _ceiling_excess(own, ceiling)
            ceiling = own if not violations else ceiling  # a spec may narrow, never widen
    else:
        ceiling = own  # type: ignore[assignment]
    violations += check_ceiling(grants, ceiling)
    if policy is not None:
        violations += policy.attestation_problems(pid, spec["data_tier"], model_role, mcp, classes)
    if violations:
        raise CeilingViolation(violations)

    # 3. readers cannot act: checked even when the ceiling allows every grant
    if policy is not None and policy.requires_reader(pid) and not reads:
        raise ReaderViolation(
            [
                f"{policy.source} marks {pid} as reading untrusted content; "
                "the spec may not declare reads_untrusted: false"
            ]
        )
    if reads:
        rproblems = reader_problems(grants, classes, pid)
        if rproblems:
            raise ReaderViolation(rproblems)

    # the MCP catalog: every server granted, reader or actor, is a reviewed, current catalog
    # server whose data may go where this profile's may (ADR-0024)
    gproblems = grant_problems(grants, classes, pid, spec["data_tier"])
    if gproblems:
        raise CatalogViolation(gproblems)

    # actors act only through the broker (ADR-0030): every profile, whatever the ceiling allows;
    # a direct exception is the policy's (a spec's own ceiling never lists one)
    direct = policy.direct_mcp(pid) if policy is not None else None
    aproblems = broker_problems(grants, classes, pid, direct)
    if aproblems:
        raise BrokerViolation(aproblems)

    # 4. include: knowledge only about what is granted (IncludeViolation), never a new grant
    include = normalise_include(spec.get("include"), grants)

    # 5. budgets
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
        "reads_untrusted": reads,
    }
    if include:
        profile["include"] = include
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


def verify_profile(
    profile: Mapping[str, Any],
    *,
    policy: CeilingPolicy | None = None,
    lock: Mapping[str, str] | None = None,
    classes: ToolClasses | None = None,
) -> list[str]:
    """Problems with an already compiled profile: schema, reader rule, ceiling, budgets, digest.

    Without ``policy`` the grants are checked against the ceiling stored *in the profile*, which
    whoever edited the profile also controls: that proves internal consistency only.  With
    ``policy`` they are checked against the policy's ceiling for the profile id, and the stored
    ceiling may not be wider.  ``lock`` maps profile ids to reviewed digests; with it, a profile
    whose digest is not the pinned one (recomputed honestly or not) is refused.

    The reader rule needs no policy: a profile that reads untrusted content (a profile without
    ``reads_untrusted`` counts as one) and holds an acting grant is refused, whatever its ceiling.
    Nor does the broker rule, except for a direct exception (the policy's ``direct_mcp``): any
    profile holding an acting grant that does not go through the broker is refused.
    """
    problems = schema_errors("agent", "profile", profile)
    if problems:
        return problems
    problems += profile_problems(profile, classes, policy)
    if (
        policy is not None
        and policy.requires_reader(profile["id"])
        and profile.get("reads_untrusted") is False
    ):
        problems.append(
            f"{policy.source} marks {profile['id']} as reading untrusted content "
            "but the profile says reads_untrusted: false"
        )
    ceiling = profile["ceiling"]
    if policy is not None:
        try:
            ceiling = policy.ceiling(profile["id"])
        except CeilingViolation as exc:
            return list(exc.problems)
        problems += _ceiling_excess(_normal_ceiling(profile["ceiling"], "profile"), ceiling)
        problems += policy.attestation_problems(
            profile["id"],
            profile.get("data_tier"),
            profile.get("model_role"),
            profile["grants"].get("mcp") or (),
            classes,
        )
    problems += check_ceiling(profile["grants"], ceiling)
    problems += check_budgets(profile["budgets"], ceiling.get("budgets"))
    try:
        if normalise_include(profile.get("include"), profile["grants"]) != profile.get(
            "include", []
        ):
            problems.append("include is not in normalised form (edited after compile?)")
    except AgentError as exc:
        problems.append(str(exc))
    if profile_digest(profile) != profile["digest"]:
        problems.append("digest does not match the profile content (edited after compile?)")
    if lock is not None:
        pinned = lock.get(profile["id"])
        if pinned is None:
            problems.append(f"{profile['id']} is not in the lock (no reviewed digest)")
        elif pinned != profile["digest"]:
            problems.append(f"digest {profile['digest']} is not the reviewed {pinned}")
    return problems


def _plain(obj: Any) -> Any:
    """JSON-plain copy (Mapping -> dict, tuple -> list) so digests are stable across loaders."""
    if isinstance(obj, Mapping):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_plain(v) for v in obj]
    return obj
