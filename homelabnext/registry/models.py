# SPDX-License-Identifier: Apache-2.0
"""Model-role aliases: resolve ``mdl:<role>`` to a concrete endpoint and model id.

Consumers name only a role (``mdl:main-reasoner``).  The role table
(``schemas/platform/model_roles.json``) maps a role to ordered bindings, each a ``svc:`` backend
plus the model id that backend serves.  The backend's address comes from the service registry
and the capability resolver, so neither a model id nor an address ever appears in a consumer.

``probe`` asks the backend what it really serves (``GET /v1/models``): the model id and, when the
role declares ``max_context_tokens``, the loaded context length; it flags a mismatch between the
alias table and the backend (K-14; :mod:`homelabnext.registry.serving` turns results into
state-diffed alerts).  Every binding can carry a pin (``version`` + ``digest``, G-11; checked by
:mod:`homelabnext.golden.pins`) and every role a rate/cost budget (``limits``, G-10; enforced by
:mod:`homelabnext.registry.limits`).  :class:`ModelClient` is a small stdlib
OpenAI-compatible client used by the golden runner and by the decision cascade.
"""

from __future__ import annotations

import json
import math
import re
import socket
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Registry
from .resolver import Endpoint, ResolutionError, Resolver

ROLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SVC_RE = re.compile(r"^svc:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
MDL_RE = re.compile(r"^mdl:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
KINDS = ("chat", "completion", "embedding")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LIMIT_KEYS = ("window_s", "max_requests", "max_tokens", "max_cost", "cost_per_1k_tokens")
#: keys an OpenAI-compatible ``/v1/models`` entry uses for the loaded context length, by engine
CONTEXT_KEYS = ("loaded_context_length", "max_model_len", "context_length", "max_context_length")


class RoleTableError(ValueError):
    """The role table is malformed.  ``problems`` lists every defect found."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


class UnknownRole(KeyError):
    pass


def normalize_role(name: str) -> str:
    """``mdl:fast-classifier`` or ``fast-classifier`` -> ``fast-classifier``."""
    m = MDL_RE.match(name)
    role = m.group(1) if m else name
    if not ROLE_RE.match(role):
        raise UnknownRole(f"{name!r} is not a model-role alias")
    return role


@dataclass(frozen=True)
class Binding:
    backend: str  # logical service name (without the svc: prefix)
    model_id: str
    priority: int = 0
    version: str | None = None  # G-11 pin: the release the backend must serve
    digest: str | None = None  # G-11 pin: sha256:<hex> of the weights

    @property
    def pinned(self) -> bool:
        return bool(self.version) and bool(self.digest and DIGEST_RE.match(self.digest))


@dataclass(frozen=True)
class Role:
    name: str
    tier: str
    bindings: tuple[Binding, ...]
    kind: str = "chat"
    fallback: str | None = None
    description: str = ""
    max_context_tokens: int | None = None
    params: Mapping[str, Any] = field(default_factory=dict)
    dimensions: int | None = None
    logprobs: bool = False
    require_model_served: bool = True
    limits: Mapping[str, float] = field(default_factory=dict)


class RoleTable:
    def __init__(self, roles: dict[str, Role], version: int = 1):
        self.roles = roles
        self.version = version

    @classmethod
    def from_dict(cls, doc: Any) -> RoleTable:
        problems: list[str] = []
        if not isinstance(doc, dict) or not isinstance(doc.get("roles"), dict):
            raise RoleTableError("role table must be a mapping with a 'roles' mapping")
        roles: dict[str, Role] = {}
        for name, r in doc["roles"].items():
            if not ROLE_RE.match(name):
                problems.append(f"role {name!r}: name must be a slug")
                continue
            if not isinstance(r, dict):
                problems.append(f"role {name}: must be a mapping")
                continue
            bindings: list[Binding] = []
            for i, b in enumerate(r.get("bindings") or []):
                m = SVC_RE.match(str(b.get("backend", "")))
                if not m:
                    problems.append(f"role {name}: bindings[{i}].backend must be a svc: id")
                    continue
                if not b.get("model_id"):
                    problems.append(f"role {name}: bindings[{i}].model_id missing")
                    continue
                digest = b.get("digest")
                if digest is not None and not DIGEST_RE.match(str(digest)):
                    problems.append(f"role {name}: bindings[{i}].digest must be sha256:<64 hex>")
                bindings.append(
                    Binding(
                        m.group(1),
                        str(b["model_id"]),
                        int(b.get("priority", 0)),
                        str(b["version"]) if b.get("version") is not None else None,
                        str(digest) if digest is not None else None,
                    )
                )
            if not bindings:
                problems.append(f"role {name}: needs at least one binding")
            kind = r.get("kind", "chat")
            if kind not in KINDS:
                problems.append(f"role {name}: kind {kind!r} not in {KINDS}")
            fb = r.get("fallback")
            fbm = MDL_RE.match(fb) if fb else None
            if fb is not None and not fbm:
                problems.append(f"role {name}: fallback {fb!r} must be an mdl: id")
            probe_cfg = r.get("probe") or {}
            limits = r.get("limits") or {}
            bad = sorted(set(limits) - set(LIMIT_KEYS)) if isinstance(limits, dict) else ["?"]
            if bad or (limits and not limits.get("window_s")):
                problems.append(f"role {name}: limits needs window_s and only {LIMIT_KEYS}")
                limits = {}
            roles[name] = Role(
                name=name,
                tier=str(r.get("tier", "")),
                bindings=tuple(sorted(bindings, key=lambda b: b.priority)),
                kind=kind,
                fallback=fbm.group(1) if fbm else None,
                description=str(r.get("description", "")),
                max_context_tokens=r.get("max_context_tokens"),
                params=dict(r.get("params") or {}),
                dimensions=r.get("dimensions"),
                logprobs=bool(r.get("logprobs", False)),
                require_model_served=bool(probe_cfg.get("require_model_served", True)),
                limits={k: float(v) for k, v in limits.items()},
            )
        for name, role in roles.items():
            seen = {name}
            cur = role.fallback
            while cur is not None:
                if cur not in roles:
                    problems.append(f"role {name}: fallback chain names unknown role {cur!r}")
                    break
                if cur in seen:
                    problems.append(f"role {name}: fallback chain loops through {cur!r}")
                    break
                seen.add(cur)
                cur = roles[cur].fallback
        if problems:
            raise RoleTableError("invalid role table", problems)
        return cls(roles, int(doc.get("version", 1)))

    @classmethod
    def load(cls, path: str | Path) -> RoleTable:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def unpinned(self) -> list[str]:
        """Every binding without a version and a sha256 digest (G-11); empty = all pinned."""
        return [
            f"mdl:{name} -> svc:{b.backend} {b.model_id}: not pinned (needs version and digest)"
            for name, r in sorted(self.roles.items())
            for b in r.bindings
            if not b.pinned
        ]

    def pins(self) -> dict[str, list[dict]]:
        """The pinned identity of every binding, role by role (what an evaluation is a function of)."""
        return {
            name: [
                {
                    "backend": f"svc:{b.backend}",
                    "model_id": b.model_id,
                    "version": b.version,
                    "digest": b.digest,
                }
                for b in r.bindings
            ]
            for name, r in sorted(self.roles.items())
        }

    def get(self, role: str) -> Role:
        name = normalize_role(role)
        try:
            return self.roles[name]
        except KeyError:
            raise UnknownRole(f"no model role {name!r}; known: {sorted(self.roles)}") from None


@dataclass(frozen=True)
class ResolvedModel:
    role: str  # the role actually used (differs from ``asked`` after a fallback)
    asked: str
    kind: str
    model_id: str
    backend: str
    endpoint: Endpoint
    params: Mapping[str, Any]
    logprobs: bool = False
    require_model_served: bool = True
    dimensions: int | None = None
    trail: tuple[str, ...] = ()
    max_context_tokens: int | None = None
    version: str | None = None
    digest: str | None = None

    @property
    def base_url(self) -> str:
        return self.endpoint.url


class ModelResolver:
    """Role alias -> backend endpoint through the registry and the capability resolver."""

    def __init__(self, registry: Registry, table: RoleTable, resolver: Resolver | None = None):
        self.registry = registry
        self.table = table
        self.resolver = resolver or Resolver(registry)

    def _capability_of(self, backend: str) -> str:
        svc = self.registry.services.get(backend) or self.registry.by_capability(backend)
        if svc is None:
            raise ResolutionError(backend, "backend is not a service in the registry")
        return svc.capability

    def resolve(self, role: str) -> ResolvedModel:
        asked = normalize_role(role)
        trail: list[str] = []
        cur: str | None = asked
        while cur is not None:
            r = self.table.get(cur)
            for b in r.bindings:
                try:
                    ep = self.resolver.resolve(self._capability_of(b.backend))
                except ResolutionError as exc:
                    trail.append(f"{cur}: svc:{b.backend} unresolved ({str(exc)[:80]})")
                    continue
                return _resolved(r, asked, b, ep, tuple(trail))
            if r.fallback:
                trail.append(f"{cur}: no binding resolved, falling back to mdl:{r.fallback}")
            cur = r.fallback
        raise ResolutionError(f"mdl:{asked}", "no binding or fallback resolved", trail)

    def resolve_binding(self, role: str, binding: Binding) -> ResolvedModel:
        """One given binding of a role, with no fallback (the egress canary runs every binding
        of a role, not the first that resolves)."""
        asked = normalize_role(role)
        r = self.table.get(asked)
        return _resolved(
            r, asked, binding, self.resolver.resolve(self._capability_of(binding.backend)), ()
        )


def _resolved(
    r: Role, asked: str, b: Binding, ep: Endpoint, trail: tuple[str, ...]
) -> ResolvedModel:
    return ResolvedModel(
        role=r.name,
        asked=asked,
        kind=r.kind,
        model_id=b.model_id,
        backend=b.backend,
        endpoint=ep,
        params=dict(r.params),
        logprobs=r.logprobs,
        require_model_served=r.require_model_served,
        dimensions=r.dimensions,
        trail=trail,
        max_context_tokens=r.max_context_tokens,
        version=b.version,
        digest=b.digest,
    )


# ---------------------------------------------------------------- HTTP plumbing
class ModelError(Exception):
    """A backend call failed.  ``kind``: unreachable | timeout | http | malformed."""

    def __init__(self, kind: str, message: str, status: int | None = None):
        self.kind = kind
        self.status = status
        super().__init__(f"{kind}: {message}")


Transport = Callable[[str, str, "dict | None", float], "tuple[int, Any]"]


def urllib_transport(method: str, url: str, body: dict | None, timeout: float):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    except TimeoutError as exc:
        raise ModelError("timeout", str(exc)) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise ModelError("timeout", str(exc.reason)) from exc
        raise ModelError("unreachable", str(exc.reason)) from exc
    except OSError as exc:
        raise ModelError("unreachable", str(exc)) from exc
    try:
        return status, (json.loads(raw.decode("utf-8")) if raw else None)
    except ValueError as exc:
        raise ModelError("malformed", f"non-JSON body (HTTP {status})", status) from exc


@dataclass(frozen=True)
class ChatResult:
    text: str
    model: str
    finish_reason: str | None
    token_logprobs: tuple[float, ...] = ()
    usage: Mapping[str, int] = field(default_factory=dict)

    @property
    def mean_prob(self) -> float | None:
        """Geometric-mean token probability, or None when no logprobs came back."""
        if not self.token_logprobs:
            return None
        return math.exp(sum(self.token_logprobs) / len(self.token_logprobs))


class ModelClient:
    """Minimal OpenAI-compatible client bound to a resolved role."""

    def __init__(
        self, model: ResolvedModel, *, timeout: float = 30.0, transport: Transport | None = None
    ):
        self.model = model
        self.timeout = timeout
        self.transport = transport or urllib_transport

    def _call(self, path: str, body: dict) -> Any:
        status, doc = self.transport("POST", f"{self.model.base_url}{path}", body, self.timeout)
        if status != 200:
            msg = ""
            if isinstance(doc, dict):
                msg = str((doc.get("error") or {}).get("message", ""))
            raise ModelError("http", f"HTTP {status} {msg}".strip(), status)
        if not isinstance(doc, dict):
            raise ModelError("malformed", "response is not an object")
        return doc

    def chat(self, messages: list[dict], *, logprobs: bool | None = None, **params: Any):
        body: dict[str, Any] = {"model": self.model.model_id, "messages": messages}
        body.update(self.model.params)
        body.update(params)
        if logprobs if logprobs is not None else self.model.logprobs:
            body["logprobs"] = True
        doc = self._call("/v1/chat/completions", body)
        try:
            choice = doc["choices"][0]
            text = choice["message"]["content"]
            lps: tuple[float, ...] = ()
            lp = choice.get("logprobs")
            if lp and lp.get("content"):
                lps = tuple(float(t["logprob"]) for t in lp["content"])
            return ChatResult(
                text=text if text is not None else "",
                model=str(doc.get("model", "")),
                finish_reason=choice.get("finish_reason"),
                token_logprobs=lps,
                usage=dict(doc.get("usage") or {}),
            )
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelError("malformed", f"unexpected chat response shape ({exc!r})") from exc

    def complete(self, prompt: str, **params: Any) -> str:
        body: dict[str, Any] = {"model": self.model.model_id, "prompt": prompt}
        body.update(params)
        doc = self._call("/v1/completions", body)
        try:
            return doc["choices"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelError("malformed", "unexpected completion response shape") from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        doc = self._call("/v1/embeddings", {"model": self.model.model_id, "input": texts})
        try:
            return [list(map(float, d["embedding"])) for d in doc["data"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelError("malformed", "unexpected embeddings response shape") from exc


# ---------------------------------------------------------------- /v1/models probe
@dataclass(frozen=True)
class ProbeResult:
    role: str
    model_id: str
    status: str  # ok | mismatch | unreachable | error
    served: tuple[str, ...] = ()
    detail: str = ""
    context_length: int | None = None  # what the backend says is loaded for this model
    expected_context: int | None = None  # the role's max_context_tokens

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def served_context(entry: Mapping[str, Any]) -> int | None:
    """The loaded context length a ``/v1/models`` entry reports, under any known engine key."""
    for src in (entry, entry.get("meta") if isinstance(entry.get("meta"), dict) else {}):
        for key in (*CONTEXT_KEYS, "n_ctx"):
            v = src.get(key)
            if isinstance(v, int) and not isinstance(v, bool) and v > 0:
                return v
    return None


def probe(
    model: ResolvedModel, *, timeout: float = 5.0, transport: Transport | None = None
) -> ProbeResult:
    """Compare the alias's bound model id (and declared context length) with what is served.

    A role that declares ``max_context_tokens`` is a mismatch when the backend reports a
    different loaded context length, or reports none at all (it cannot be verified, K-14).
    """
    tr = transport or urllib_transport
    want_ctx = model.max_context_tokens
    try:
        status, doc = tr("GET", f"{model.base_url}/v1/models", None, timeout)
    except ModelError as exc:
        st = "unreachable" if exc.kind in ("unreachable", "timeout") else "error"
        return ProbeResult(
            model.role, model.model_id, st, detail=str(exc), expected_context=want_ctx
        )
    if status != 200 or not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        return ProbeResult(model.role, model.model_id, "error", detail=f"HTTP {status}, bad body",
                           expected_context=want_ctx)  # fmt: skip
    entries = {str(m.get("id")): m for m in doc["data"] if isinstance(m, dict)}
    served = tuple(sorted(entries))
    if model.model_id not in served:
        detail = f"alias binds {model.model_id!r} but backend serves {list(served)}"
        st = "mismatch" if model.require_model_served else "ok"
        return ProbeResult(model.role, model.model_id, st, served, detail, None, want_ctx)
    ctx = served_context(entries[model.model_id])
    if want_ctx is not None and ctx != want_ctx:
        detail = (
            f"{model.model_id!r} loaded with context {ctx} but the role declares {want_ctx}"
            if ctx is not None
            else f"{model.model_id!r}: backend does not report its loaded context length "
            f"(role declares {want_ctx})"
        )
        return ProbeResult(model.role, model.model_id, "mismatch", served, detail, ctx, want_ctx)
    return ProbeResult(model.role, model.model_id, "ok", served, "", ctx, want_ctx)


def probe_all(
    resolver: ModelResolver, *, timeout: float = 5.0, transport: Transport | None = None
) -> list[ProbeResult]:
    out: list[ProbeResult] = []
    for name in sorted(resolver.table.roles):
        try:
            rm = resolver.resolve(name)
        except ResolutionError as exc:
            out.append(ProbeResult(name, "", "unreachable", detail=str(exc).splitlines()[0]))
            continue
        out.append(probe(rm, timeout=timeout, transport=transport))
    return out
