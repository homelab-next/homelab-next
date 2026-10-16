# SPDX-License-Identifier: Apache-2.0
"""In-memory versioned secret store with leases and an injected clock."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from conformance.protocols.secrets import (
    InvalidPath,
    Lease,
    LeaseError,
    Secret,
    SecretNotFound,
)


class FakeSecretStore:
    features = frozenset({"clock-control"})

    def __init__(self, clock: Callable[[], float] | None = None):
        self._now = 1_000.0
        self._clock = clock or (lambda: self._now)
        self._v: dict[str, list[dict[str, str]]] = {}
        self._leases: dict[str, tuple[Lease, bool]] = {}
        self._n = 0

    def tick(self, seconds: float) -> None:
        self._now += seconds

    @staticmethod
    def _check_path(path: str, data: Mapping[str, str] | None = None) -> None:
        segs = path.split("/") if isinstance(path, str) else []
        if not path or any(s in ("", ".", "..") for s in segs):
            # NOTE: the message names the path only - never the values being stored
            raise InvalidPath(f"invalid secret path {path!r}")

    def put(self, path: str, data: Mapping[str, str]) -> int:
        self._check_path(path, data)
        if not data or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise ValueError("data must be a non-empty mapping of str to str")
        self._v.setdefault(path, []).append(dict(data))
        return len(self._v[path])

    def get(self, path: str, version: int | None = None) -> Secret:
        versions = self._v.get(path)
        if not versions:
            raise SecretNotFound(f"no secret at {path!r}")
        v = len(versions) if version is None else version
        if not 1 <= v <= len(versions):
            raise SecretNotFound(f"no version {v} at {path!r}")
        return Secret(path, v, dict(versions[v - 1]))

    def delete(self, path: str) -> None:
        if path not in self._v:
            raise SecretNotFound(f"no secret at {path!r}")
        del self._v[path]

    def list(self, prefix: str = "") -> list[str]:
        return sorted(p for p in self._v if p.startswith(prefix))

    def lease(self, path: str, ttl: float) -> Lease:
        if ttl <= 0:
            raise LeaseError("ttl must be positive")
        sec = self.get(path)
        self._n += 1
        lease = Lease(f"lease-{self._n}", path, self._clock() + ttl, dict(sec.data))
        self._leases[lease.id] = (lease, False)
        return lease

    def lease_valid(self, lease_id: str) -> bool:
        item = self._leases.get(lease_id)
        if item is None:
            return False
        lease, revoked = item
        return not revoked and self._clock() < lease.expires_at

    def revoke(self, lease_id: str) -> None:
        item = self._leases.get(lease_id)
        if item is not None:
            self._leases[lease_id] = (item[0], True)


class LeakyErrorSecretStore(FakeSecretStore):
    """Defect: the invalid-path error echoes the submitted values."""

    @staticmethod
    def _check_path(path, data=None):
        try:
            FakeSecretStore._check_path(path, data)
        except InvalidPath as exc:
            raise InvalidPath(f"{exc}; rejected payload {dict(data or {})!r}") from None
