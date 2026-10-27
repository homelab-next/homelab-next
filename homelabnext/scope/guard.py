# SPDX-License-Identifier: Apache-2.0
"""The scope guard: ``in_scope(target) -> Decision`` and the decorator writer tools wear.

Every reference a tool passes (logical id, bare name, FQDN, address, ``vmid:<n>``, a registered
alias) is **resolved to one canonical logical id first**; the decision is made on the canonical
target only.  A different spelling of an out-of-scope target therefore cannot slip past, and a
reference that does not resolve, or resolves to two different targets, is refused (fail closed)
unless the policy says ``unknown: allow``.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import ipaddress
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .policy import ScopePolicy

DENY_CODES = (
    "explicit-out",
    "override-out",
    "vmid-threshold",
    "out-tag",
    "unknown-target",
    "ambiguous-target",
)
EVENT_TYPE = "homelabnext.scope.denied"


@dataclass(frozen=True)
class Target:
    """What the guard needs to know about one thing a tool might write about."""

    id: str
    aliases: tuple[str, ...] = ()
    vmid: int | None = None
    tags: tuple[str, ...] = ()
    scope: str | None = None  # None = not stated; "in" / "out" = stated on the target itself
    parent: str | None = None  # the id of the target this runs on (a service's host guest)


@dataclass(frozen=True)
class Decision:
    allow: bool
    target: str  # the reference exactly as the caller passed it
    canonical: str | None
    code: (
        str  # a DENY_CODES value, or "allowed" / "explicit-in" / "override-in" / "unknown-allowed"
    )
    reason: str

    @property
    def verdict(self) -> str:
        return "allow" if self.allow else "deny"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "target": self.target,
            "canonical": self.canonical,
            "code": self.code,
            "reason": self.reason,
        }

    def as_event(
        self,
        *,
        tool: str | None = None,
        source: str = "svc:scope-guard",
        time: str | None = None,
    ) -> dict[str, Any]:
        """The ``homelabnext.scope.denied`` event for a denial (ValueError for an allow)."""
        if self.allow:
            raise ValueError("only a denial becomes a scope.denied event")
        from homelabnext.events import build_event

        data: dict[str, Any] = {
            "target": self.target,
            "canonical": self.canonical,
            "code": self.code,
            "reason": self.reason,
        }
        if tool:
            data["tool"] = tool
        # Identity = who asked about what, when: two denials at different times are two events.
        stamp = time or ""
        return build_event(
            EVENT_TYPE,
            source,
            data,
            dedupe_key=f"{tool or ''}|{self.target}|{self.code}|{stamp}",
            subject=self.canonical or None,
            severity="info",
            time=time,
        )


class ScopeDenied(Exception):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"out of scope: {decision.target}: {decision.reason}")


#: a dotted IPv4 address with one to four parts, each decimal, octal (leading 0) or hex (0x): the
#: spellings ``inet_aton`` accepts, which a tool handing the reference to the C resolver reaches
_V4_PARTS = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\Z")


def _ip_spelling(text: str) -> tuple[str | None, bool]:
    """``(canonical, odd)`` for a reference that is an IP address, ``(None, False)`` otherwise.

    ``canonical`` is the one spelling targets are keyed by: IPv6 compressed, an IPv4 address
    written inside IPv6 (IPv4-compatible ``::a.b.c.d``, IPv4-mapped, IPv4-translated
    ``::ffff:0:a.b.c.d``, NAT64's RFC 6052 well-known prefix) as that IPv4 address, and an IPv4
    address in hex, octal, integer or short dotted form as its dotted-quad form.  ``odd`` says the
    reference was not written that way; NAT64's local-use prefix (RFC 8215, where the IPv4
    address sits depends on the operator's prefix length) has no canonical form: ``(None, True)``.
    """
    from homelabnext.modules.scope import EMBEDDED_V4

    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        if not _V4_PARTS.match(text):
            return None, False
        try:
            packed = socket.inet_aton(text)
        except OSError:
            return None, False
        return str(ipaddress.IPv4Address(packed)), True
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ip), str(ip) != text
    for net in EMBEDDED_V4:
        if ip in net:
            if net.prefixlen != 96:
                return None, True
            return str(ipaddress.IPv4Address(int(ip) & 0xFFFF_FFFF)), True
    return str(ip), str(ip) != text


def _norm(ref: str) -> str:
    """A name lower-cased without its trailing dot; an IP address in its one canonical spelling
    (:func:`_ip_spelling`), so a longer or embedded spelling of an address resolves to the same
    target."""
    text = ref.strip().lower().rstrip(".")
    canonical, _ = _ip_spelling(text)
    return canonical or text


def _odd_address(ref: str) -> bool:
    """Whether ``ref`` is an IP address written in any but its canonical spelling."""
    return isinstance(ref, str) and _ip_spelling(ref.strip().lower().rstrip("."))[1]


class ScopeGuard:
    def __init__(
        self,
        targets: Iterable[Target],
        policy: ScopePolicy | None = None,
        *,
        resolver: Any = None,
    ) -> None:
        """``resolver``: optional logical-id resolver (``homelabnext.ids.Resolver``) mapping an
        alias id to a canonical id; consulted when a reference is not a known name."""
        self.policy = policy or ScopePolicy()
        self.resolver = resolver
        self._targets: dict[str, Target] = {}
        self._alias: dict[str, set[str]] = {}
        for t in targets:
            if t.id in self._targets:
                raise ValueError(f"duplicate target {t.id!r}")
            self._targets[t.id] = t
            names = {t.id, *t.aliases}
            if t.id.startswith("guest:"):  # a guest's slug is its hostname
                names.add(t.id.partition(":")[2])
            for n in names:
                self._alias.setdefault(_norm(n), set()).add(t.id)

    # ---------------------------------------------------------------- resolution
    def resolve(self, ref: str) -> tuple[str | None, str | None]:
        """(canonical id, None) | (None, "unknown-target" | "ambiguous-target")."""
        if not isinstance(ref, str) or not ref.strip():
            return None, "unknown-target"
        hits = self._alias.get(_norm(ref), set())
        if len(hits) > 1:
            return None, "ambiguous-target"
        if hits:
            return next(iter(hits)), None
        if self.resolver is not None:
            try:
                got = self.resolver.resolve(ref)
            except Exception:  # unresolved id, or not an id at all
                return None, "unknown-target"
            hits = self._alias.get(_norm(str(got)), set())
            if len(hits) == 1:
                return next(iter(hits)), None
            if len(hits) > 1:
                return None, "ambiguous-target"
        return None, "unknown-target"

    # ---------------------------------------------------------------- decision
    def in_scope(self, ref: str) -> Decision:
        """Decide for ``ref``.

        A target with a ``parent`` (a service on its host guest) can only narrow the parent's
        scope: the parent is decided first, and a parent denial (its own ``scope: out``, a
        threshold, an out tag, an override) denies the child whatever the child says about
        itself.  Only a policy override naming the child itself beats that.
        """
        canonical, why = self.resolve(ref)
        if canonical is None:
            if why == "unknown-target" and _odd_address(ref):
                # an address spelt around its canonical form (embedded in IPv6, hex, octal, an
                # integer) that names no target: the spelling a tool would use to reach a target
                # it could not name plainly, so refused whatever the policy says about unknowns
                return Decision(
                    False,
                    ref,
                    None,
                    "unknown-target",
                    "an address in a non-canonical or embedded spelling that does not resolve",
                )
            if why == "unknown-target" and self.policy.unknown == "allow":
                return Decision(
                    True, ref, None, "unknown-allowed", "unknown target allowed by policy"
                )
            msg = (
                "reference matches more than one target"
                if why == "ambiguous-target"
                else "reference does not resolve to a known target"
            )
            return Decision(False, ref, None, why or "unknown-target", msg)
        return self._decide(ref, canonical, set())

    def _decide(self, ref: str, canonical: str, seen: set[str]) -> Decision:
        t = self._targets[canonical]
        p = self.policy
        ov = p.overrides.get(canonical)
        if ov == "out":
            return Decision(False, ref, canonical, "override-out", "policy override marks it out")
        if ov == "in":
            return Decision(True, ref, canonical, "override-in", "policy override marks it in")
        if t.parent is not None and t.parent in self._targets and t.parent not in seen:
            up = self._decide(t.parent, t.parent, seen | {canonical})
            if not up.allow:
                return Decision(False, ref, canonical, up.code, f"host {t.parent}: {up.reason}")
        if t.scope == "out":
            return Decision(False, ref, canonical, "explicit-out", "target is marked scope: out")
        if t.scope == "in":
            return Decision(True, ref, canonical, "explicit-in", "target is marked scope: in")
        if p.vmid_threshold is not None and t.vmid is not None and t.vmid > p.vmid_threshold:
            return Decision(
                False,
                ref,
                canonical,
                "vmid-threshold",
                f"vmid {t.vmid} is above the scope threshold {p.vmid_threshold}",
            )
        bad = sorted(set(t.tags) & p.out_tags)
        if bad:
            return Decision(
                False, ref, canonical, "out-tag", f"carries out-of-scope tag {bad[0]!r}"
            )
        return Decision(True, ref, canonical, "allowed", "in scope")

    def require(self, ref: str) -> Decision:
        d = self.in_scope(ref)
        if not d.allow:
            raise ScopeDenied(d)
        return d


# ---------------------------------------------------------------- the writer-tool decorator
def guarded(
    guard: ScopeGuard,
    *,
    target_arg: str = "target",
    tool: str | None = None,
    sink: Callable[[dict[str, Any]], Any] | None = None,
    on_deny: str = "return",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a writer tool so it runs only for an in-scope target.

    The guard runs BEFORE the tool body, so nothing is written for a denied target.  On denial
    the wrapper returns ``{"ok": False, "denied": <decision dict>}`` (``on_deny="return"``) or
    raises :class:`ScopeDenied` (``on_deny="raise"``); either way ``sink`` receives the
    ``homelabnext.scope.denied`` event (a failing sink never turns a denial into a write).
    """
    if on_deny not in ("return", "raise"):
        raise ValueError("on_deny must be 'return' or 'raise'")

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)
        if target_arg not in sig.parameters:
            raise TypeError(f"{fn.__name__} has no parameter {target_arg!r}")
        name = tool or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            ref = bound.arguments[target_arg]
            d = guard.in_scope(ref if isinstance(ref, str) else "")
            if d.allow:
                return fn(*args, **kwargs)
            if sink is not None:
                with contextlib.suppress(Exception):
                    sink(d.as_event(tool=name if len(name) <= 64 else None))
            if on_deny == "raise":
                raise ScopeDenied(d)
            return {"ok": False, "denied": d.as_dict()}

        wrapper.__scope_guarded__ = True  # type: ignore[attr-defined]
        return wrapper

    return deco


# ---------------------------------------------------------------- adapters from the models
def targets_from_fleet(fleet: Any) -> list[Target]:
    """Targets for every guest of a ``homelabnext.compute.Fleet``."""
    out = []
    for g in fleet.sorted():
        aliases = [g.name, fleet.fqdn(g), *g.addresses]  # network.ip and every extra address
        if g.vmid is not None:
            aliases.append(f"vmid:{g.vmid}")
        out.append(
            Target(
                id=g.id,
                aliases=tuple(aliases),
                vmid=g.vmid,
                tags=tuple(g.tags),
                scope=g.raw.get("scope"),
            )
        )
    return out


def targets_from_services(
    registry_doc: Mapping[str, Any], guests: Iterable[Target] = ()
) -> list[Target]:
    """Targets for every service of a registry document (``svc:<name>``).

    A service on a guest named like its host (``guest:<host>``, when among ``guests``) gets that
    guest as its ``parent`` and inherits its vmid and tags: the host is decided first, so marking
    a scratch guest out covers what runs on it, and a service's own ``scope: in`` cannot undo it
    (only narrow it).
    """
    by_id = {t.id: t for t in guests}
    out = []
    for name, svc in sorted((registry_doc.get("services") or {}).items()):
        host = by_id.get(f"guest:{svc.get('host', '')}")
        scope = svc.get("scope") or (host.scope if host else None)
        tags = tuple(svc.get("tags", [])) + (host.tags if host else ())
        aliases = [svc["capability"]] if svc.get("capability") else []
        out.append(
            Target(
                id=f"svc:{name}",
                aliases=tuple(aliases),
                vmid=host.vmid if host else None,
                tags=tags,
                scope=scope,
                parent=host.id if host else None,
            )
        )
    return out
