# SPDX-License-Identifier: Apache-2.0
"""The ``secrets`` contract on OpenBao (pinned: openbao 2.1, dev mode in the lab), stdlib HTTP.

``make(**config)`` builds an :class:`OpenBaoStore` on ``HNX_ENDPOINT_SECRETS`` with the token in
the environment variable ``token_env`` (the lab's throwaway ``LAB_SECRETS_DEV_TOKEN``), read at
request time so no object holds it.

Mapping:

* **Versioned values** are KV version 2 (``<mount>/data/<path>``).  ``put`` writes a version and
  returns its number, ``get`` reads the latest or ``?version=N`` (N >= 1: KV v2 reads 0 as
  "latest", so 0 and negative versions are refused as absent before any request), ``delete``
  removes the metadata (every version), ``list`` walks ``<mount>/metadata/...?list=true``.
  Every path lives under a namespace (``hnx-conform/<random>`` per subject in scratch mode,
  removed on ``close()``).
  KV v2 answers 204 to deleting a path that is not there, so ``delete`` reads the metadata first
  to raise ``SecretNotFound``.
* **Leases.**  KV v2 has no leases: its reads carry no lease id and nothing to revoke.  The
  mechanism OpenBao does have for "time-limited access" is a **token**: ``lease(path, ttl)``
  creates a non-renewable child token with ``ttl`` and a policy that may only read this
  namespace, reads the value *with that token*, and returns the token's **accessor** as the lease
  id (an accessor is OpenBao's non-secret handle on a token; the token itself is dropped).
  ``lease_valid`` is ``auth/token/lookup-accessor`` (valid while the token lives, and only for
  tokens this store minted, recognised by their metadata); ``revoke`` is
  ``auth/token/revoke-accessor``, and an accessor already gone counts as revoked.  Expiry is the
  server's: OpenBao revokes the token when its TTL lapses.
* **Redaction.**  Errors carry the operation, path and HTTP status only, never a request or
  response body, and are raised outside any ``except`` block so no exception that saw a body is
  on the chain.  ``Secret``/``Lease`` reprs are the contract's redacted ones.

Findings: KV v2 keeps ``max_versions`` versions per path (10 by default); older ones are pruned,
so "old versions remain readable" holds only within that bound.  Token TTLs are whole seconds,
so a fractional ``ttl`` is rounded up (a lease never ends earlier than asked).
"""

from __future__ import annotations

import json
import math
import secrets as _random
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from conformance.protocols.secrets import (
    InvalidPath,
    Lease,
    LeaseError,
    Secret,
    SecretNotFound,
    SecretsError,
)
from homelabnext._http import check_plaintext, read_bounded, safe_urlopen

from ._env import env_secret, resolve

__all__ = ["OpenBaoError", "OpenBaoStore", "make"]

_LEASE_META = "hnx_lease"


class OpenBaoError(SecretsError):
    """OpenBao answered with an unexpected status, or could not be reached."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _check_path(path: str) -> list[str]:
    segs = path.split("/") if isinstance(path, str) else []
    if not path or any(s in ("", ".", "..") for s in segs):
        raise InvalidPath(f"invalid secret path {path!r}")  # the path only, never the values
    return segs


class OpenBaoStore:
    """:class:`conformance.protocols.secrets.SecretStore` on OpenBao KV v2 plus token leases."""

    features: frozenset[str] = frozenset()

    def __init__(
        self,
        base_url: str,
        token: Callable[[], str],
        *,
        mount: str = "secret",
        namespace: str = "hnx",
        ensure_mount: bool = False,
        scratch: bool = False,
        timeout: float = 10.0,
        allow_plaintext: bool = False,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        _check_path(mount)
        _check_path(namespace)
        self._base = base_url.rstrip("/")
        self._token = token
        self.mount, self.namespace = mount.strip("/"), namespace.strip("/")
        self.timeout = timeout
        self._scratch = scratch
        self._clock, self._sleep = clock, sleep
        self.policy = "hnx-lease-" + self.namespace.replace("/", "-")
        self._policy_ready = False
        if ensure_mount:
            self._ensure_mount()

    def __repr__(self) -> str:
        return f"OpenBaoStore(mount={self.mount!r}, namespace={self.namespace!r})"

    # ---------------------------------------------------------------- transport
    def _call(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """``(status, json)``; never raises from inside an ``except`` with a body in scope."""
        headers = {"X-Vault-Token": token or self._token(), "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"{self._base}/v1/{path}", data=data, headers=headers, method=method
        )
        status, raw, failure = 0, b"", ""
        try:
            with safe_urlopen(req, timeout=self.timeout) as resp:
                status, raw = int(resp.status), read_bounded(resp)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            exc.close()
        except (urllib.error.URLError, OSError) as exc:
            failure = type(exc).__name__
        del req, data, body  # nothing that saw a value outlives the call
        if failure:
            raise OpenBaoError(f"{method} {self._safe(path)}: transport error: {failure}")
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        return status, doc if isinstance(doc, dict) else {}

    @staticmethod
    def _safe(path: str) -> str:
        return path.split("?", 1)[0]

    def _fail(self, what: str, path: str, status: int) -> OpenBaoError:
        return OpenBaoError(f"{what} {path!r}: OpenBao answered HTTP {status}", status)

    def _kv(self, kind: str, path: str) -> str:
        return f"{self.mount}/{kind}/{self.namespace}/{urllib.parse.quote(path, safe='/')}"

    def _ensure_mount(self) -> None:
        status, doc = self._call("GET", f"sys/mounts/{self.mount}")
        if status == 200:
            opts = (doc.get("data") or doc).get("options") or {}
            if str(opts.get("version")) != "2":
                raise OpenBaoError(f"mount {self.mount!r} is not KV version 2")
            return
        status, _ = self._call(
            "POST", f"sys/mounts/{self.mount}", {"type": "kv", "options": {"version": "2"}}
        )
        if status not in (200, 204):
            raise self._fail("enable kv-v2 at", self.mount, status)
        for _ in range(100):  # a fresh KV v2 mount upgrades itself before it takes writes
            if self._call("GET", f"{self.mount}/config")[0] == 200:
                return
            self._sleep(0.1)
        raise OpenBaoError(f"mount {self.mount!r} did not become ready")

    # ---------------------------------------------------------------- versioned values
    def put(self, path: str, data: Mapping[str, str]) -> int:
        _check_path(path)
        if not data or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise ValueError("data must be a non-empty mapping of str to str")
        status, doc = self._call("POST", self._kv("data", path), {"data": dict(data)})
        if status != 200:
            raise self._fail("put", path, status)
        return int((doc.get("data") or {}).get("version", 0))

    def get(self, path: str, version: int | None = None) -> Secret:
        _check_path(path)
        if version is not None and int(version) < 1:
            # KV v2 reads ``?version=0`` as "the latest"; the Protocol numbers versions from 1,
            # so 0 and anything negative name a version that was never written
            raise SecretNotFound(f"no secret at {path!r} version {int(version)}")
        q = "" if version is None else f"?version={int(version)}"
        status, doc = self._call("GET", self._kv("data", path) + q)
        if status == 404:
            raise SecretNotFound(f"no secret at {path!r}" + (f" version {version}" if q else ""))
        if status != 200:
            raise self._fail("get", path, status)
        inner = doc.get("data") or {}
        values, meta = inner.get("data"), inner.get("metadata") or {}
        if values is None:  # a deleted or destroyed version
            raise SecretNotFound(f"no secret at {path!r}" + (f" version {version}" if q else ""))
        return Secret(
            path,
            int(meta.get("version", version or 0)),
            {str(k): str(v) for k, v in values.items()},
        )

    def delete(self, path: str) -> None:
        _check_path(path)
        status, _ = self._call("GET", self._kv("metadata", path))
        if status == 404:
            raise SecretNotFound(f"no secret at {path!r}")
        if status != 200:
            raise self._fail("delete", path, status)
        status, _ = self._call("DELETE", self._kv("metadata", path))
        if status not in (200, 204):
            raise self._fail("delete", path, status)

    def _list_dir(self, folder: str) -> list[str]:
        sub = f"{self.mount}/metadata/{self.namespace}/{urllib.parse.quote(folder, safe='/')}"
        status, doc = self._call("GET", sub + "?list=true")
        if status == 404:
            return []
        if status != 200:
            raise self._fail("list", folder or "/", status)
        return [str(k) for k in (doc.get("data") or {}).get("keys") or []]

    def list(self, prefix: str = "") -> Sequence[str]:
        if not isinstance(prefix, str) or ".." in prefix.split("/"):
            raise InvalidPath(f"invalid prefix {prefix!r}")
        out: list[str] = []
        start = prefix.rsplit("/", 1)[0] + "/" if "/" in prefix else ""
        todo = [start]
        while todo:
            folder = todo.pop()
            for key in self._list_dir(folder):
                full = folder + key
                if not (full.startswith(prefix) or prefix.startswith(full)):
                    continue
                if key.endswith("/"):
                    todo.append(full)
                elif full.startswith(prefix):
                    out.append(full)
        return sorted(out)

    # ---------------------------------------------------------------- leases (tokens)
    def _ensure_policy(self) -> None:
        if self._policy_ready:
            return
        rules = f'path "{self.mount}/data/{self.namespace}/*" {{ capabilities = ["read"] }}\n'
        status, _ = self._call("PUT", f"sys/policies/acl/{self.policy}", {"policy": rules})
        if status not in (200, 204):
            raise self._fail("write lease policy", self.policy, status)
        self._policy_ready = True

    def lease(self, path: str, ttl: float) -> Lease:
        _check_path(path)
        if not isinstance(ttl, int | float) or not math.isfinite(ttl) or not ttl > 0:
            # refused before anything is written: math.ceil(inf) would raise OverflowError only
            # after the lease policy was already in place
            raise LeaseError("ttl must be a positive, finite number of seconds")
        self.get(path)  # SecretNotFound before any token is minted
        self._ensure_policy()
        seconds = max(1, math.ceil(ttl))
        status, doc = self._call(
            "POST",
            "auth/token/create",
            {
                "policies": [self.policy],
                "ttl": f"{seconds}s",
                "explicit_max_ttl": f"{seconds}s",
                "renewable": False,
                "no_default_policy": True,
                "display_name": "hnx-lease",
                "meta": {_LEASE_META: self.namespace, "path": path},
            },
        )
        auth = doc.get("auth") or {}
        if status != 200 or not auth.get("accessor") or not auth.get("client_token"):
            raise self._fail("lease", path, status)
        issued = self._clock()
        child = str(auth["client_token"])
        status, rdoc = self._call("GET", self._kv("data", path), token=child)
        del child
        values = ((rdoc.get("data") or {}).get("data")) if status == 200 else None
        if values is None:
            self.revoke(str(auth["accessor"]))
            raise self._fail("read through lease for", path, status)
        lease_s = float(auth.get("lease_duration") or seconds)
        return Lease(
            str(auth["accessor"]),
            path,
            issued + lease_s,
            {str(k): str(v) for k, v in values.items()},
        )

    def lease_valid(self, lease_id: str) -> bool:
        if not isinstance(lease_id, str) or not lease_id:
            return False
        status, doc = self._call("POST", "auth/token/lookup-accessor", {"accessor": lease_id})
        if status in (400, 403, 404):  # invalid accessor / expired ("bad token") / unknown
            return False
        if status != 200:
            raise OpenBaoError(f"lease lookup: OpenBao answered HTTP {status}", status)
        meta = (doc.get("data") or {}).get("meta") or {}
        return meta.get(_LEASE_META) == self.namespace

    def revoke(self, lease_id: str) -> None:
        if not isinstance(lease_id, str) or not lease_id:
            return
        status, _ = self._call("POST", "auth/token/revoke-accessor", {"accessor": lease_id})
        if status not in (200, 204, 400, 403, 404):  # already gone is revoked
            raise OpenBaoError(f"revoke: OpenBao answered HTTP {status}", status)

    # ---------------------------------------------------------------- lifecycle
    def close(self) -> None:
        if not self._scratch:
            return
        for path in self.list(""):
            self._call("DELETE", self._kv("metadata", path))
        if self._policy_ready:
            self._call("DELETE", f"sys/policies/acl/{self.policy}")


def make(
    *,
    token_env: str = "LAB_SECRETS_DEV_TOKEN",
    mount: str = "secret",
    namespace: str | None = None,
    scratch: bool = True,
    ensure_mount: bool = True,
    timeout: float = 10.0,
    allow_plaintext: bool = False,
    capability: str = "secrets",
) -> OpenBaoStore:
    """A store on the ``secrets`` endpoint.  ``scratch`` gives each subject its own namespace,
    removed on ``close()``; otherwise ``namespace`` names a standing one."""
    if scratch:
        namespace = namespace or f"hnx-conform/{_random.token_hex(6)}"
    elif not namespace:
        raise ValueError("a standing store needs a namespace")
    return OpenBaoStore(
        resolve(capability, env_only=True, schemes=("http", "https")).url,
        env_secret(token_env),
        mount=mount,
        namespace=namespace,
        ensure_mount=ensure_mount,
        scratch=scratch,
        timeout=timeout,
        allow_plaintext=allow_plaintext,
    )
