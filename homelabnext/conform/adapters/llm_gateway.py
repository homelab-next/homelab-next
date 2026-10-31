# SPDX-License-Identifier: Apache-2.0
"""The ``inference`` contract through an LLM gateway (LiteLLM proxy or Bifrost), stdlib HTTP.

``make(**config)`` returns a :class:`GatewayTarget`: the library's own
:class:`~homelabnext.conform.adapters.openai_compat.OpenAICompat` client on the gateway endpoint
(``HNX_ENDPOINT_<CAPABILITY>``, default ``HNX_ENDPOINT_LLM_GATEWAY``), calling with the gateway's
admin key, plus the three methods of feature ``gateway``
(:class:`conformance.protocols.inference.GatewayClient`):

* ``declared_models()`` - the role aliases of the role table the gateway config was generated from
  (``roles``, a path relative to the checkout), so ``/v1/models`` is compared with the source of
  truth rather than with itself;
* ``with_key(token)`` - the same endpoint with another bearer key, or none;
* ``throttled()`` - a client on the key that the generated config limits (``throttle_key``,
  ``throttle_model``, ``throttle_requests``: the lab's ``conformance-throttle`` key);
* ``over_ceiling()`` (feature ``tlp-ceiling``) - a client on a key whose sending TLP ceiling is
  above a cloud role's (``over_ceiling_key``), the role it must be refused
  (``over_ceiling_model``) and one it may call (``over_ceiling_served``).

Keys are ``secret:`` references, read from ``HNX_SECRET_<NAME>`` at every call (never held).
Nothing here is product specific: the same target file shape serves LiteLLM and Bifrost, so a
gateway swap is a target file plus this suite (docs/llm-gateway.md).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from homelabnext.registry.model import secret_env_name
from homelabnext.registry.models import RoleTable

from ._env import AdapterConfigError, env_secret, resolve
from .openai_compat import OpenAICompat

__all__ = ["GatewayTarget", "make"]


class GatewayTarget(OpenAICompat):
    def __init__(
        self,
        base_url: str,
        *,
        key_env: str,
        declared: Sequence[str],
        throttle: tuple[str, str, int] | None = None,
        over_ceiling: tuple[str, str, str] | None = None,
        model: str | None = None,
        timeout: float = 30.0,
        features: Sequence[str] = ("embeddings", "streaming", "gateway"),
        allow_plaintext: bool = False,
    ):
        read = env_secret(key_env)
        super().__init__(
            base_url,
            auth=lambda: f"Bearer {read()}",
            timeout=timeout,
            features=features,
            allow_plaintext=allow_plaintext,
        )
        self._url = base_url
        self._declared = list(declared)
        self._throttle = throttle
        self._over = over_ceiling
        self._timeout = timeout
        self._plaintext = allow_plaintext
        if model:
            self.model = model

    def __repr__(self) -> str:
        return "GatewayTarget(<endpoint>)"

    def declared_models(self) -> list[str]:
        return list(self._declared)

    def with_key(self, token: str | None) -> OpenAICompat:
        return OpenAICompat(
            self._url,
            auth=lambda: f"Bearer {token}" if token else None,
            timeout=self._timeout,
            allow_plaintext=self._plaintext,
        )

    def throttled(self) -> tuple[OpenAICompat, str, int]:
        if self._throttle is None:
            raise AdapterConfigError(
                "feature gateway needs throttle_key, throttle_model, throttle_requests"
            )
        env, model, n = self._throttle
        return self._keyed(env), model, n

    def over_ceiling(self) -> tuple[OpenAICompat, str, str]:
        if self._over is None:
            raise AdapterConfigError(
                "feature tlp-ceiling needs over_ceiling_key, over_ceiling_model, "
                "over_ceiling_served"
            )
        env, refused, served = self._over
        return self._keyed(env), refused, served

    def _keyed(self, env: str) -> OpenAICompat:
        """A client on the key held in ``env``, read at every call."""
        read = env_secret(env)
        return OpenAICompat(
            self._url,
            auth=lambda: f"Bearer {read()}",
            timeout=self._timeout,
            allow_plaintext=self._plaintext,
        )


def make(
    *,
    roles: str,
    key: str = "secret:llm-gateway/master-key",
    throttle_key: str | None = None,
    throttle_model: str | None = None,
    throttle_requests: int | None = None,
    over_ceiling_key: str | None = None,
    over_ceiling_model: str | None = None,
    over_ceiling_served: str | None = None,
    model: str | None = None,
    capability: str = "llm-gateway",
    timeout: float = 30.0,
    allow_plaintext: bool = False,
) -> GatewayTarget:
    """A gateway target.  ``roles`` is the role table the gateway config was generated from."""
    from homelabnext.conform.registry import find_root

    path = Path(roles)
    if not path.is_absolute():
        path = find_root(None) / path
    try:
        declared = sorted(RoleTable.load(path).roles)
    except (OSError, ValueError) as exc:
        raise AdapterConfigError(f"roles: cannot read the role table {roles}: {exc}") from exc
    throttle = None
    if throttle_key or throttle_model or throttle_requests:
        if not (throttle_key and throttle_model and throttle_requests):
            raise AdapterConfigError(
                "throttle_key, throttle_model and throttle_requests go together"
            )
        throttle = (secret_env_name(throttle_key), throttle_model, int(throttle_requests))
    over = None
    if over_ceiling_key or over_ceiling_model or over_ceiling_served:
        if not (over_ceiling_key and over_ceiling_model and over_ceiling_served):
            raise AdapterConfigError(
                "over_ceiling_key, over_ceiling_model and over_ceiling_served go together"
            )
        over = (secret_env_name(over_ceiling_key), over_ceiling_model, over_ceiling_served)
    ep = resolve(capability, env_only=True, schemes=("http", "https"))
    return GatewayTarget(
        ep.url,
        key_env=secret_env_name(key),
        declared=declared,
        throttle=throttle,
        over_ceiling=over,
        model=model,
        timeout=timeout,
        allow_plaintext=allow_plaintext,
    )
