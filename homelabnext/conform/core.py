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
skipped by raising :class:`Skip` or by requiring a feature the target does not declare.

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
    "Capability",
    "CheckResult",
    "Mutant",
    "Skip",
    "Suite",
    "run_checks",
]

SEVERITIES = ("must", "should")
STATUSES = ("pass", "fail", "skip", "waived")
_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class Skip(Exception):
    """Raised by a check that cannot be evaluated against this subject (reason in the message)."""


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check.  ``check`` is the check id; ``ok`` is False only for a failure.

    ``status`` is ``pass``, ``fail``, ``skip`` (feature not declared) or ``waived`` (a ``should``
    check the target waived, with a reason).  Skipped and waived results have ``ok=True`` but
    never count as a pass of anything that matters.
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


@dataclass
class Suite:
    """A capability's checks plus the metadata the docs and the report need."""

    name: str
    summary: str
    protocol: str = ""  # dotted path of the Protocol the subject implements
    tier: str = "core"  # core: one of the fourteen capabilities; extended: additional suites
    _specs: dict[str, CheckSpec] = field(default_factory=dict, init=False, repr=False)

    def check(
        self,
        id: str,
        summary: str,
        *,
        severity: str = "must",
        requires: Iterable[str] = (),
    ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
        if not _ID.match(id):
            raise ValueError(f"check id {id!r} must be lower-case words joined by '-'")
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
        if id in self._specs:
            raise ValueError(f"duplicate check id {id!r} in suite {self.name!r}")

        def deco(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
            self._specs[id] = CheckSpec(id, summary, severity, tuple(requires), fn)
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


@dataclass(frozen=True)
class Mutant:
    """A deliberately defective subject.  The suite MUST fail the check named in ``fails``."""

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
