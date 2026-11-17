# SPDX-License-Identifier: Apache-2.0
"""The ``inference`` contract on one OpenAI-compatible model server, stdlib HTTP.

``make(**config)`` returns the library's own
:class:`~homelabnext.conform.adapters.openai_compat.OpenAICompat` client on the endpoint
``HNX_ENDPOINT_INFERENCE`` (never a default), so the suite in ``conformance/suites/inference.py``
runs against an engine that serves one model directly, with no gateway in front of it.  The
server's own API key is optional: with ``key`` (a ``secret:`` reference) the client sends it as a
bearer key, read from ``HNX_SECRET_<NAME>`` at every call and never held.

``model`` names the id the checks ask for (default: the first one ``/v1/models`` lists);
``embed_model`` the one the embeddings checks use.  ``features`` is what the target declares the
engine serves (``streaming``, ``embeddings``), which must be what the module's slot entry says.

Findings (fidelity limits of the engine, not of this adapter): an engine that serves exactly one
model and ignores the ``model`` field of a request answers any id with its own, so the check
``unknown-model-rejected`` fails against it directly; the gateway in front of it is what holds the
role allow-list (docs/llm-gateway.md), and the suite passes there.
"""

from __future__ import annotations

from collections.abc import Sequence

from homelabnext.registry.model import secret_env_name

from ._env import AdapterConfigError, env_secret, resolve
from .openai_compat import OpenAICompat

__all__ = ["InferenceServer", "make"]

_FEATURES = ("streaming", "embeddings")


class InferenceServer(OpenAICompat):
    """An OpenAI-compatible client that names the model the checks call."""

    def __init__(
        self,
        base_url: str,
        *,
        key_env: str | None = None,
        model: str | None = None,
        embed_model: str | None = None,
        timeout: float = 30.0,
        features: Sequence[str] = ("streaming",),
        allow_plaintext: bool = False,
    ):
        auth = None
        if key_env:
            read = env_secret(key_env)

            def auth() -> str:
                return f"Bearer {read()}"

        super().__init__(
            base_url,
            auth=auth,
            timeout=timeout,
            features=features,
            allow_plaintext=allow_plaintext,
        )
        if model:
            self.model = model
        if embed_model:
            self.embed_model = embed_model


def make(
    *,
    key: str | None = None,
    model: str | None = None,
    embed_model: str | None = None,
    features: Sequence[str] = ("streaming",),
    timeout: float = 30.0,
    allow_plaintext: bool = False,
    capability: str = "inference",
) -> InferenceServer:
    """A target on the endpoint ``HNX_ENDPOINT_<CAPABILITY>``; no default URL, no default key."""
    unknown = sorted(set(features) - set(_FEATURES))
    if unknown:
        raise AdapterConfigError(f"features: {unknown} are not inference features {_FEATURES}")
    ep = resolve(capability, env_only=True, schemes=("http", "https"))
    return InferenceServer(
        ep.url,
        key_env=secret_env_name(key) if key else None,
        model=model,
        embed_model=embed_model,
        timeout=timeout,
        features=tuple(features),
        allow_plaintext=allow_plaintext,
    )
