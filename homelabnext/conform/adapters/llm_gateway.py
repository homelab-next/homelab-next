# SPDX-License-Identifier: Apache-2.0
"""The ``inference`` contract through an LLM gateway (the LiteLLM proxy), stdlib HTTP.

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
  (``over_ceiling_model``) and one it may call (``over_ceiling_served``);
* ``tlp_admit()`` and ``refused_fallback()`` (feature ``tlp-admit``, a gateway that reads the
  ``X-HNX-TLP`` header, ADR-0038) - a client on a key whose sending ceiling is ``clear``
  (``tlp_sender_key``), the admin key, a role that leaves the lab (``tlp_model``) and one that
  stays in it (``tlp_local_model``); and a role whose deployments fail and whose first fallback is
  refused at admission (``failover_model``, optional);
* ``turn_records()`` (feature ``turn-records``, the lab's own gateway) - sends a few calls tagged
  ``X-HNX-Tag`` (two tags of this run, two calls refused by TLP when ``tlp_model`` is set) on
  ``turn_model`` (default ``model``), then reads them back through
  :mod:`homelabnext.conform.adapters.gateway_usage` with the telemetry reader's key
  (``telemetry_key``).

``embed_model`` names the embedding role the embeddings checks call (default: ``model``).

Keys are ``secret:`` references, read from ``HNX_SECRET_<NAME>`` at every call (never held).
Nothing here is product specific: the target file shape is the gateway contract, so a gateway
swap (ADR-0022 names the documented exit) is a target file plus this suite (docs/llm-gateway.md).
"""

from __future__ import annotations

import math
import time
from collections.abc import Sequence
from pathlib import Path

from homelabnext.registry.model import secret_env_name
from homelabnext.registry.models import RoleTable

from ._env import AdapterConfigError, env_secret, resolve, run_token
from .openai_compat import InferenceError, OpenAICompat

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
        embed_model: str | None = None,
        tlp_admit: tuple[str, str, str] | None = None,
        failover_model: str | None = None,
        telemetry_key: str | None = None,
        turn_model: str | None = None,
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
        self._key_env = key_env
        self._tlp = tlp_admit
        self._failover = failover_model
        self._telemetry = telemetry_key
        self._turn_model = turn_model or model
        self._turns: tuple | None = None
        if model:
            self.model = model
        if embed_model:
            self.embed_model = embed_model

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

    def tlp_admit(self) -> tuple[OpenAICompat, OpenAICompat, str, str]:
        if self._tlp is None:
            raise AdapterConfigError(
                "feature tlp-admit needs tlp_sender_key, tlp_model and tlp_local_model"
            )
        env, leaving, local = self._tlp
        return self._keyed(env), self._keyed(self._key_env), leaving, local

    def refused_fallback(self) -> tuple[OpenAICompat, str] | None:
        if self._failover is None:
            return None
        return self._keyed(self._key_env), self._failover

    def turn_records(self):
        """Tagged calls of this run, then the usage log's turn source over their window.  The
        calls are sent once per run and gateway (:data:`_SENT`): the suite builds a subject per
        check, and every turn-records check reads the same window."""
        from .gateway_usage import UsageReader, UsageTurnSource

        if self._telemetry is None or not self._turn_model:
            raise AdapterConfigError("feature turn-records needs telemetry_key and turn_model")
        sent = (self._url, run_token(), self._turn_model, self._telemetry)
        if self._turns is None and sent in _SENT:
            self._turns = _SENT[sent]
        if self._turns is None:
            source = UsageTurnSource(
                UsageReader(
                    self._url,
                    self._telemetry,
                    timeout=self._timeout,
                    allow_plaintext=self._plaintext,
                )
            )
            tags = [f"hnx-conform-{run_token()}-a", f"hnx-conform-{run_token()}-b"]
            admin = self._keyed(self._key_env)
            start = math.floor(time.time())
            for tag in (tags[0], tags[0], tags[1]):
                admin.chat_fields(self._turn_model, _TURN_PROMPT, [("X-HNX-Tag", tag)])
            if self._tlp is not None:
                # two identical refusals: turns of status failure, error_code 403, which a
                # gateway that aggregates refusals (count) records once
                sender = self._keyed(self._tlp[0])
                for _ in range(2):
                    try:
                        sender.chat_fields(self._tlp[1], _TURN_PROMPT, [("X-HNX-Tag", tags[1])])
                    except InferenceError as exc:
                        if exc.status != 403:
                            raise
            end = math.ceil(time.time()) + 1
            self._turns = _SENT[sent] = (source, float(start), float(end), tags)
        return self._turns

    def _keyed(self, env: str) -> OpenAICompat:
        """A client on the key held in ``env``, read at every call."""
        read = env_secret(env)
        return OpenAICompat(
            self._url,
            auth=lambda: f"Bearer {read()}",
            timeout=self._timeout,
            allow_plaintext=self._plaintext,
        )


_TURN_PROMPT = [{"role": "user", "content": "Say hello in one short sentence."}]
#: (gateway URL, run token, model, telemetry key) -> what turn_records() returned for them
_SENT: dict[tuple[str, str, str | None, str | None], tuple] = {}


def _together(names: Sequence[str], values: Sequence[object]) -> bool:
    """Whether the options ``names`` are all given (True) or none (False); else a config error."""
    if all(values):
        return True
    if any(values):
        raise AdapterConfigError(f"{', '.join(names)} go together")
    return False


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
    embed_model: str | None = None,
    tlp_sender_key: str | None = None,
    tlp_model: str | None = None,
    tlp_local_model: str | None = None,
    failover_model: str | None = None,
    telemetry_key: str | None = None,
    turn_model: str | None = None,
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
    tlp_admit = None
    names = ("tlp_sender_key", "tlp_model", "tlp_local_model")
    if _together(names, (tlp_sender_key, tlp_model, tlp_local_model)):
        tlp_admit = (secret_env_name(str(tlp_sender_key)), str(tlp_model), str(tlp_local_model))
    for opt, name in (
        ("model", model), ("embed_model", embed_model), ("tlp_model", tlp_model),
        ("tlp_local_model", tlp_local_model), ("failover_model", failover_model),
        ("turn_model", turn_model),
    ):  # fmt: skip
        if name and name not in declared:
            raise AdapterConfigError(f"{opt}: {name!r} is not a role of {roles}")
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
        embed_model=embed_model,
        tlp_admit=tlp_admit,
        failover_model=failover_model,
        telemetry_key=telemetry_key,
        turn_model=turn_model,
    )
