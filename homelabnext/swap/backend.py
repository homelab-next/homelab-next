# SPDX-License-Identifier: Apache-2.0
"""What the swap runner needs from the world, as one small interface.

The runner (``machine.py``) owns ordering, gates, evidence and the record. Everything that touches
a real system (start the candidate, mirror writes, compare, edit the registry, stop the old
component, scan for leftovers) goes through a :class:`Backend`, so the same state machine drives a
pair of fake lakes in a unit test and a real product swap on a server.

Every method returns an :class:`Outcome`. A method a backend does not implement fails its gate
with a clear message instead of passing silently; ``ok`` is never assumed.

:class:`ManualBackend` is the one the CLI uses by default: gates are satisfied by *attestation
files* (JSON with ``"ok": true``) that the operator produced elsewhere, each hashed into the
evidence, plus the real registry flip and the real decommission scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .decommission import Retired, retired_from_record, scan
from .flip import FlipError, flip_text, load_doc, plan_flip
from .record import sha256_file


@dataclass
class Outcome:
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class Backend:
    """Base class: every operation is "not implemented" until a subclass provides it."""

    def _missing(self, name: str) -> Outcome:
        return Outcome(False, f"backend {type(self).__name__} does not implement {name}")

    def conformance(self, role: str) -> Outcome:  # role: "old" | "new"
        return self._missing("conformance")

    def shadow_start(self) -> Outcome:
        return self._missing("shadow_start")

    def start_mirror(self) -> Outcome:
        return self._missing("start_mirror")

    def mirror_status(self) -> Outcome:
        """``data['unresolved']``: divergences not yet reconciled."""
        return self._missing("mirror_status")

    def stop_mirror(self) -> Outcome:
        return self._missing("stop_mirror")

    def parity(self) -> Outcome:
        """``ok`` iff parity holds; ``data['rows_compared']`` and ``data['report']`` if known."""
        return self._missing("parity")

    def preview_route(self, target: dict[str, Any]) -> Outcome:
        return self._missing("preview_route")

    def apply_route(self, target: dict[str, Any]) -> Outcome:
        return self._missing("apply_route")

    def verify_route(self, target: dict[str, Any]) -> Outcome:
        """The canary: does the alias now answer from ``target``?"""
        return self._missing("verify_route")

    def stop_old(self) -> Outcome:
        return self._missing("stop_old")

    def start_old(self) -> Outcome:
        return self._missing("start_old")

    def old_state(self) -> Outcome:
        """``data['state']`` is ``running``, ``stopped`` or ``destroyed``."""
        return self._missing("old_state")

    def discard_parked(self, reason: str) -> Outcome:
        """Drop, on purpose, the writes the old component refuses (``SwapRunner.rollback(...,
        abandon_parked=True)``; a refused write only, not those queued behind it, and nothing
        while the component is unreachable); ``data['discarded']`` lists them, rows included,
        for the evidence."""
        return self._missing("discard_parked")

    def restore_parked(self, batches: list[dict[str, Any]]) -> Outcome:
        """Park again batches :meth:`discard_parked` returned (their evidence could not be
        written), in their write order."""
        return self._missing("restore_parked")

    def decommission_scan(self) -> Outcome:
        return self._missing("decommission_scan")


class ManualBackend(Backend):
    """Operator-attested gates plus the real registry flip and decommission scan."""

    ATTESTATIONS = (
        "conformance-old",
        "conformance-new",
        "shadow",
        "mirror",
        "parity",
        "canary",
        "old-stopped",
    )

    def __init__(
        self,
        *,
        attestations: dict[str, str | Path] | None = None,
        registry: str | Path | None = None,
        service: str | None = None,
        scan_roots: list[str | Path] | None = None,
        retired: Retired | None = None,
        allow: list[str] | None = None,
        inventory: list[str | Path] | None = None,
    ):
        for k in attestations or {}:
            if k not in self.ATTESTATIONS:
                raise ValueError(
                    f"unknown attestation {k!r}; known: {', '.join(self.ATTESTATIONS)}"
                )
        self.attestations = {k: Path(v) for k, v in (attestations or {}).items()}
        self.registry = Path(registry) if registry else None
        self.service = service
        self.scan_roots = list(scan_roots or [])
        self.retired = retired
        self.allow = list(allow or [])
        self.inventory = list(inventory or [])

    # -- helpers
    def _attest(self, name: str) -> Outcome:
        p = self.attestations.get(name)
        if p is None:
            return Outcome(False, f"no attestation {name!r}: pass --attest {name}=FILE")
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return Outcome(False, f"attestation {name!r} unreadable: {exc}")
        if not isinstance(doc, dict) or doc.get("ok") is not True:
            return Outcome(
                False, f"attestation {name!r} does not say ok: true", {"attestation": name}
            )
        data = {"attestation": name, "sha256": sha256_file(p), "content": doc}
        return Outcome(True, f"attested ({name})", data)

    # -- Backend
    def conformance(self, role: str) -> Outcome:
        return self._attest(f"conformance-{role}")

    def shadow_start(self) -> Outcome:
        return self._attest("shadow")

    def start_mirror(self) -> Outcome:
        return self._attest("mirror")

    def mirror_status(self) -> Outcome:
        o = self._attest("mirror")
        if o.ok:
            o.data["unresolved"] = int(o.data["content"].get("unresolved", 0))
        return o

    def stop_mirror(self) -> Outcome:
        return Outcome(True, "mirror stop is recorded; stop the tee in the deployment")

    def discard_parked(self, reason: str) -> Outcome:
        return Outcome(
            True, "this backend parks nothing (the deployment's tee is reconciled by hand)",
            {"discarded": []},
        )  # fmt: skip

    def parity(self) -> Outcome:
        o = self._attest("parity")
        if o.ok:
            o.data["rows_compared"] = int(o.data["content"].get("rows_compared", 0))
        return o

    def _plan(self, target: dict[str, Any]):
        if self.registry is None or self.service is None:
            raise FlipError("no registry/service configured for the route")
        doc = load_doc(self.registry.read_text(encoding="utf-8"))
        return doc, plan_flip(
            doc,
            self.service,
            host=target.get("host"),
            port=target.get("port"),
            impl=target.get("impl"),
            version=target.get("version"),
        )

    def preview_route(self, target: dict[str, Any]) -> Outcome:
        try:
            _, plan = self._plan(target)
        except (FlipError, OSError) as exc:
            return Outcome(False, str(exc))
        return Outcome(True, plan.diff(), {"diff": plan.diff(), "plan": plan.to_dict()})

    def apply_route(self, target: dict[str, Any]) -> Outcome:
        try:
            _, plan = self._plan(target)
            assert self.registry is not None
            if not plan.empty:
                text = self.registry.read_text(encoding="utf-8")
                self.registry.write_text(flip_text(text, plan), encoding="utf-8")
        except (FlipError, OSError) as exc:
            return Outcome(False, str(exc))
        return Outcome(True, plan.diff(), {"diff": plan.diff(), "plan": plan.to_dict()})

    def verify_route(self, target: dict[str, Any]) -> Outcome:
        try:
            _, plan = self._plan(target)
        except (FlipError, OSError) as exc:
            return Outcome(False, str(exc))
        if not plan.empty:
            return Outcome(
                False, "registry does not yet point at the target", {"pending": plan.diff()}
            )
        canary = self._attest("canary")
        return canary

    def stop_old(self) -> Outcome:
        return self._attest("old-stopped")

    def start_old(self) -> Outcome:
        return Outcome(True, "start the old component by hand; recorded in the rollback")

    def old_state(self) -> Outcome:
        o = self._attest("old-stopped")
        return Outcome(o.ok, o.detail, {"state": "stopped" if o.ok else "running"})

    def decommission_scan(self) -> Outcome:
        if self.retired is None or not self.scan_roots:
            return Outcome(False, "no retired names or scan roots configured for the scan")
        found = scan(
            self.scan_roots,
            self.retired,
            registry=self.registry,
            inventory=self.inventory,
            allow=self.allow,
        )
        return Outcome(
            not found,
            "no references remain" if not found else f"{len(found)} references remain",
            {"findings": [f.to_dict() for f in found]},
        )


__all__ = ["Backend", "ManualBackend", "Outcome", "retired_from_record"]
