# SPDX-License-Identifier: Apache-2.0
"""The module's own code passes the ``context`` suite through its HTTP routes (the shared adapter
``homelabnext.conform.adapters.context_service``, CI's stand-in for a run against the model): the
store with the semantic adapter's test seams, every read a JSON request through the service's
routes.  The semantic SHOULD needs the real model (modules/context/conformance/target.yml)."""

from __future__ import annotations

import pytest

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.adapters.context_service import make
from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_suite
from homelabnext.context_semantic import SemanticContextStore
from tests.context.test_semantic import _FakeBm25, _FakeEmbedder


def _factory(tlp_of):
    return SemanticContextStore(
        ceiling="red", tlp_of=tlp_of, embedder=_FakeEmbedder(), sparse_factory=_FakeBm25
    )


def test_the_service_routes_pass_every_must_of_the_context_suite():
    results = run_checks(load_suite("context"), lambda: make(store_factory=_factory, features=()))
    failed = {r.check: r.evidence for r in results if not r.ok}
    assert failed == {}
    assert sum(r.status == "pass" for r in results) >= 13


def test_without_a_model_the_adapter_says_what_is_missing(monkeypatch):
    monkeypatch.delenv("HNX_CONTEXT_MODEL_DIR", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_CONTEXT_MODEL_DIR"):
        make()
