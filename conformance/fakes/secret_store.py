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


class ChainedLeakSecretStore(FakeSecretStore):
    """Defect: the error's message is clean but it is raised *from* one carrying the values."""

    @staticmethod
    def _check_path(path, data=None):
        try:
            FakeSecretStore._check_path(path, data)
        except InvalidPath:
            try:
                raise ValueError(f"validation context: payload={dict(data or {})}")
            except ValueError as inner:
                raise InvalidPath(f"invalid secret path {path!r}") from inner


class NeverExpiringSecretStore(FakeSecretStore):
    """Defect: a lease stays valid after its ttl (only revocation ends it)."""

    def lease_valid(self, lease_id: str) -> bool:
        item = self._leases.get(lease_id)
        return item is not None and not item[1]


class UnknownLeaseValidSecretStore(FakeSecretStore):
    """Defect: a lease id the store never issued is reported valid."""

    def lease_valid(self, lease_id: str) -> bool:
        if lease_id not in self._leases:
            return True
        return super().lease_valid(lease_id)


class NegativeTtlSecretStore(FakeSecretStore):
    """Defect: only a zero ttl is refused; a negative one makes an already-expired lease."""

    def lease(self, path: str, ttl: float) -> Lease:
        if ttl == 0:
            raise LeaseError("ttl must be positive")
        sec = self.get(path)
        self._n += 1
        lease = Lease(f"lease-{self._n}", path, self._clock() + ttl, dict(sec.data))
        self._leases[lease.id] = (lease, False)
        return lease


class VersionZeroIsLatestSecretStore(FakeSecretStore):
    """Defect: ``version=0`` is read as "no version given", so it returns the latest."""

    def get(self, path: str, version: int | None = None) -> Secret:
        return super().get(path, version or None)


class NegativeVersionSecretStore(FakeSecretStore):
    """Defect: only the upper bound is checked, so a negative version indexes from the end."""

    def get(self, path: str, version: int | None = None) -> Secret:
        versions = self._v.get(path)
        if not versions:
            raise SecretNotFound(f"no secret at {path!r}")
        v = len(versions) if version is None else version
        if v > len(versions):
            raise SecretNotFound(f"no version {v} at {path!r}")
        return Secret(path, v, dict(versions[v - 1]))


class VersionErrorLeaksSecretStore(FakeSecretStore):
    """Defect: the "no such version" error of a path that holds a secret echoes the latest
    value."""

    def get(self, path: str, version: int | None = None) -> Secret:
        versions = self._v.get(path)
        if versions and version is not None and not 1 <= version <= len(versions):
            raise SecretNotFound(f"no version {version} at {path!r}; latest is {versions[-1]}")
        return super().get(path, version)


class DeletesLatestOnlySecretStore(FakeSecretStore):
    """Defect: ``delete`` removes the latest version only; older versions stay readable."""

    def delete(self, path: str) -> None:
        if path not in self._v:
            raise SecretNotFound(f"no secret at {path!r}")
        self._v[path].pop()
        if not self._v[path]:
            del self._v[path]


class AliasingSecretStore(FakeSecretStore):
    """Defect: the caller's mapping is stored and handed back by reference, so changing it after
    ``put`` (or changing what ``get`` returned) rewrites the stored secret."""

    def put(self, path: str, data: Mapping[str, str]) -> int:
        self._check_path(path, data)
        self._v.setdefault(path, []).append(data)  # type: ignore[arg-type]
        return len(self._v[path])

    def get(self, path: str, version: int | None = None) -> Secret:
        s = super().get(path, version)
        return Secret(s.path, s.version, self._v[path][s.version - 1])
