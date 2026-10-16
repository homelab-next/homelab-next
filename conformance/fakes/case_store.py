# SPDX-License-Identifier: Apache-2.0
"""In-memory case management: alerts, promotion to cases, notes, status machine."""

from __future__ import annotations

from dataclasses import replace

from conformance.protocols.cases import (
    SEVERITIES,
    Alert,
    Case,
    CaseClosed,
    InvalidTransition,
    NotFound,
)

_NEXT = {"open": ("in_progress", "closed"), "in_progress": ("closed",), "closed": ("open",)}


class FakeCaseStore:
    features = frozenset()

    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}
        self._cases: dict[str, Case] = {}
        self._dedup: dict[str, str] = {}
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n:04d}"

    def create_alert(self, source, title, severity, *, dedup_key=None):
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if not source or not title:
            raise ValueError("source and title are required")
        if dedup_key and dedup_key in self._dedup:
            cur = self._alerts[self._dedup[dedup_key]]
            if cur.status == "new":
                bumped = replace(cur, count=cur.count + 1)
                self._alerts[cur.id] = bumped
                return bumped
        alert = Alert(self._id("alert"), source, title, severity, "new")
        self._alerts[alert.id] = alert
        if dedup_key:
            self._dedup[dedup_key] = alert.id
        return alert

    def get_alert(self, alert_id):
        try:
            return self._alerts[alert_id]
        except KeyError:
            raise NotFound(alert_id) from None

    def list_alerts(self, status=None):
        return [a for a in self._alerts.values() if status in (None, a.status)]

    def promote(self, alert_id, title=None):
        alert = self.get_alert(alert_id)
        if alert.status == "promoted":
            return self._cases[alert.case_id]
        if alert.status == "dismissed":
            raise InvalidTransition("a dismissed alert cannot be promoted")
        case = Case(self._id("case"), title or alert.title, "open", (alert.id,))
        self._cases[case.id] = case
        self._alerts[alert.id] = replace(alert, status="promoted", case_id=case.id)
        return case

    def dismiss(self, alert_id, reason):
        alert = self.get_alert(alert_id)
        if not reason or not reason.strip():
            raise ValueError("a dismissal needs a reason")
        if alert.status == "promoted":
            raise InvalidTransition("a promoted alert cannot be dismissed")
        self._alerts[alert.id] = replace(alert, status="dismissed", reason=reason.strip())
        return self._alerts[alert.id]

    def get_case(self, case_id):
        try:
            return self._cases[case_id]
        except KeyError:
            raise NotFound(case_id) from None

    def add_note(self, case_id, author, text):
        case = self.get_case(case_id)
        if case.status == "closed":
            raise CaseClosed(case_id)
        if not author or not text:
            raise ValueError("author and text are required")
        self._cases[case_id] = replace(case, notes=(*case.notes, (author, text)))
        return self._cases[case_id]

    def set_status(self, case_id, status, *, resolution=None):
        case = self.get_case(case_id)
        if status not in _NEXT.get(case.status, ()):
            raise InvalidTransition(f"{case.status} -> {status} is not allowed")
        if status == "closed" and not (resolution and resolution.strip()):
            raise ValueError("closing a case needs a resolution")
        self._cases[case_id] = replace(
            case, status=status, resolution=resolution if status == "closed" else None
        )
        return self._cases[case_id]


class NoReasonCaseStore(FakeCaseStore):
    """Defect: alerts can be dismissed without any reason."""

    def dismiss(self, alert_id, reason):
        alert = self.get_alert(alert_id)
        self._alerts[alert.id] = replace(alert, status="dismissed", reason=(reason or "").strip())
        return self._alerts[alert.id]
