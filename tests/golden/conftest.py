# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "models"))

from models_support import make_registry, role_doc

from conformance.fakes.openai_server import FakeOpenAIServer
from homelabnext.registry import FakeDNS, Resolver
from homelabnext.registry.models import ModelResolver, RoleTable


@pytest.fixture
def build_resolver():
    started = []

    def build(small_rules, large_rules=()):
        small = FakeOpenAIServer(
            models=["example-4b"], rules=list(small_rules), default_reply="Hello"
        ).start()
        large = FakeOpenAIServer(
            models=["example-27b"], rules=list(large_rules), default_reply="Hello"
        ).start()
        started.extend([small, large])
        env = {"HNX_ENDPOINT_INFERENCE_SMALL": small.url, "HNX_ENDPOINT_INFERENCE_LARGE": large.url}
        reg = make_registry()
        res = Resolver(reg, dns=FakeDNS(), hosts={}, environ=env)
        return ModelResolver(reg, RoleTable.from_dict(role_doc()), res), small, large

    yield build
    for s in started:
        s.stop()
