# SPDX-License-Identifier: Apache-2.0
"""Suite format: named checks with a severity, run against any implementation of a contract.

A *suite* belongs to one capability and holds checks.  A check is a function of one argument,
the *subject* (an object implementing the capability's contract, built by the target's adapter
factory).  The same suite therefore proves the incumbent product and a replacement:

    suite = Suite("object-store", "S3-like blob storage")

    @suite.check("put-get-roundtrip", "bytes written are the bytes read back")
    def _(store):
        store.put("b", "k", b"x")
        assert store.get("b", "k") == b"x"

A check passes by returning (or returning ``None``), fails by raising ``AssertionError`` (the
message becomes the evidence) or by letting the subject raise anything unexpected, and is
skipped by requiring a product feature the target does not declare, or - only when the check is
declared ``skippable=True`` - by raising :class:`Skip` from the suite's own code.  A ``Skip``
raised by the subject (or from a check not declared skippable) is a failure: the subject does not
get to decide that it was not tested.

Features are of two kinds.  *Product* features (``streaming``, ``wildcards``, ...) describe what
the implementation offers; a check needing one is skipped when it is absent.  *Test hooks*
(:data:`TEST_HOOKS`: ``clock-control``, ``fault-injection``) only let the suite reach a state; a
``must`` check that needs an undeclared hook is ``untested``, which fails like a failure - not
declaring a hook cannot be a way around a MUST.

Severity follows RFC 2119 loosely: ``must`` is part of the contract (a failure fails the
capability and the exit code); ``should`` is expected behaviour whose absence is reported but
does not fail the capability unless ``--strict`` is given.  A ``must`` check cannot be waived.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "SEVERITIES",
    "STATUSES",
    "TEST_HOOKS",
    "Capability",
    "CheckResult",
    "Mutant",
    "Skip",
    "Suite",
    "run_checks",
]

SEVERITIES = ("must", "should")
STATUSES = ("pass", "fail", "skip", "waived", "untested")
#: features that are harness hooks rather than product abilities (see the module docstring)
TEST_HOOKS = frozenset({"clock-control", "fault-injection"})
_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class Skip(Exception):
    """Raised by a ``skippable`` check that cannot be evaluated against this subject.

    Honoured only when raised from the module that defines the check (the suite), never when it
    comes out of the subject: an adapter that raises ``Skip`` fails the check.
    """


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check.  ``check`` is the check id; ``ok`` is False only for a failure.

    ``status`` is ``pass``, ``fail``, ``skip`` (product feature not declared), ``waived`` (a
    ``should`` check the target waived, with a reason) or ``untested`` (a ``must`` check that
    needs a test hook the target does not declare; ``ok=False``).  Skipped and waived results
    have ``ok=True`` but never count as a pass of anything that matters.
    """

    check: str
    ok: bool
    evidence: str
    severity: str = "must"
    status: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        if not self.status:
            object.__setattr__(self, "status", "pass" if self.ok else "fail")
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, got {self.status!r}")

    @property
    def counts_as_pass(self) -> bool:
        return self.status == "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "status": self.status,
            "ok": self.ok,
            "evidence": self.evidence,
        }


class Capability(Protocol):
    """What the runner needs from a suite (matches ``docs/interfaces.md``)."""

    name: str

    def checks(self) -> Sequence[Callable[[Any], CheckResult]]: ...


@dataclass(frozen=True)
class CheckSpec:
    id: str
    summary: str
    severity: str
    requires: tuple[str, ...]
    fn: Callable[[Any], Any]
    skippable: bool = False

    @property
    def can_skip(self) -> bool:
        """True when this check can end without executing (a mutant must not rely on it)."""
        return self.skippable or bool(self.requires)


@dataclass
class Suite:
    """A capability's checks plus the metadata the docs and the report need."""

    name: str
    summary: str
    protocol: str = ""  # dotted path of the Protocol the subject implements
    tier: str = "core"  # core: one of the fifteen capabilities; extended: additional suites
    _specs: dict[str, CheckSpec] = field(default_factory=dict, init=False, repr=False)

    def check(
        self,
        id: str,
        summary: str,
        *,
        severity: str = "must",
        requires: Iterable[str] = (),
        skippable: bool = False,
    ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
        if not _ID.match(id):
            raise ValueError(f"check id {id!r} must be lower-case words joined by '-'")
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
        if id in self._specs:
            raise ValueError(f"duplicate check id {id!r} in suite {self.name!r}")

        def deco(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
            self._specs[id] = CheckSpec(id, summary, severity, tuple(requires), fn, skippable)
            return fn

        return deco

    # -- Capability protocol -------------------------------------------------------------
    @property
    def specs(self) -> list[CheckSpec]:
        return list(self._specs.values())

    def ids(self) -> list[str]:
        return list(self._specs)

    def checks(self) -> list[Callable[[Any], CheckResult]]:
        return [self.bind(s.id) for s in self._specs.values()]

    def bind(self, check_id: str, features: Iterable[str] | None = None) -> Callable[[Any], Any]:
        """The check as a function ``subject -> CheckResult`` (never raises)."""
        spec = self._specs[check_id]

        def run_one(subject: Any) -> CheckResult:
            have = set(getattr(subject, "features", ())) | set(features or ())
            missing = [r for r in spec.requires if r not in have]
            hooks = [r for r in missing if r in TEST_HOOKS]
            if hooks and spec.severity == "must":
                return CheckResult(
                    spec.id,
                    False,
                    f"untested: MUST check needs test hook(s) {', '.join(hooks)} that the target "
                    "does not declare",
                    spec.severity,
                    "untested",
                )
            if missing:
                return CheckResult(
                    spec.id,
                    True,
                    f"skipped: target does not declare feature(s) {', '.join(missing)}",
                    spec.severity,
                    "skip",
                )
            try:
                out = spec.fn(subject)
            except Skip as sk:
                why = _foreign_skip(spec, sk)
                if why:
                    return CheckResult(spec.id, False, why, spec.severity)
                return CheckResult(spec.id, True, f"skipped: {sk}", spec.severity, "skip")
            except AssertionError as exc:
                return CheckResult(spec.id, False, str(exc) or "assertion failed", spec.severity)
            except Exception as exc:  # the subject misbehaved: that is a contract violation
                return CheckResult(
                    spec.id, False, f"raised {type(exc).__name__}: {exc}", spec.severity
                )
            if isinstance(out, CheckResult):
                return out
            return CheckResult(spec.id, True, out if isinstance(out, str) else "ok", spec.severity)

        run_one.check_id = spec.id  # type: ignore[attr-defined]
        run_one.severity = spec.severity  # type: ignore[attr-defined]
        run_one.summary = spec.summary  # type: ignore[attr-defined]
        return run_one


def _foreign_skip(spec: CheckSpec, sk: Skip) -> str | None:
    """Why a ``Skip`` must not be honoured, or None when the suite itself raised it."""
    if not spec.skippable:
        return f"raised Skip ({sk}) but the check is not skippable: only the suite may skip"
    tb = sk.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    origin = tb.tb_frame.f_code.co_filename if tb is not None else ""
    if origin != spec.fn.__code__.co_filename:
        return f"the subject raised Skip ({sk}): only the suite may skip a check"
    return None


@dataclass(frozen=True)
class Mutant:
    """A deliberately defective subject.  The suite MUST fail the check named in ``fails``.

    That check must be one that always executes (no ``requires``, not ``skippable``): a mutant
    caught only by a check that can skip proves nothing about a target on which it skips.
    """

    factory: Callable[[], Any]
    fails: str
    description: str


def run_checks(
    suite: Suite,
    make_subject: Callable[[], Any],
    *,
    features: Iterable[str] | None = None,
    waive: Mapping[str, str] | None = None,
    only: Iterable[str] | None = None,
) -> list[CheckResult]:
    """Run every check of ``suite``, each against a *fresh* subject from ``make_subject``.

    A fresh subject per check keeps checks independent.  A real-service adapter should make each
    subject use its own namespace (prefix, bucket, topic) so the checks do not see each other.
    Subjects with a ``close()`` method are closed afterwards.  A factory that raises is not a
    check failure: the exception propagates (the run could not be measured).
    """
    waive = dict(waive or {})
    for cid, reason in waive.items():
        spec = suite._specs.get(cid)
        if spec is None:
            raise ValueError(f"waive: {suite.name} has no check {cid!r}")
        if spec.severity == "must":
            raise ValueError(f"waive: {cid} is a MUST check and cannot be waived")
        if not str(reason).strip():
            raise ValueError(f"waive: {cid} needs a reason")
    wanted = set(only) if only is not None else None
    if wanted is not None:
        unknown = sorted(wanted - set(suite._specs))
        if unknown:
            raise ValueError(f"{suite.name} has no check(s) {', '.join(unknown)}")
    results: list[CheckResult] = []
    for spec in suite.specs:
        if wanted is not None and spec.id not in wanted:
            continue
        if spec.id in waive:
            results.append(
                CheckResult(spec.id, True, f"waived: {waive[spec.id]}", spec.severity, "waived")
            )
            continue
        subject = make_subject()
        try:
            results.append(suite.bind(spec.id, features)(subject))
        finally:
            close = getattr(subject, "close", None)
            if callable(close):
                close()
    return results
