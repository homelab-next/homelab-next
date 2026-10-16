# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from models_support import make_registry, role_doc

from conformance.fakes.openai_server import FakeOpenAIServer
from homelabnext.registry import FakeDNS, Resolver
from homelabnext.registry.models import ModelResolver, RoleTable


@pytest.fixture
def registry():
    return make_registry()


@pytest.fixture
def servers():
    large = FakeOpenAIServer(models=["example-27b"], default_reply="large says hi").start()
    small = FakeOpenAIServer(
        models=["example-4b", "example-embed-8d"], default_reply="small says hi", logprob=-0.05
    ).start()
    yield large, small
    large.stop()
    small.stop()


@pytest.fixture
def make_resolver(registry, servers):
    large, small = servers

    def build(doc=None, env=None):
        environ = {
            "HNX_ENDPOINT_INFERENCE_LARGE": large.url,
            "HNX_ENDPOINT_INFERENCE_SMALL": small.url,
        }
        environ.update(env or {})
        resolver = Resolver(registry, dns=FakeDNS(), hosts={}, environ=environ)
        return ModelResolver(registry, RoleTable.from_dict(doc or role_doc()), resolver)

    return build
