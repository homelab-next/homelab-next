# SPDX-License-Identifier: Apache-2.0
"""Role alias -> endpoint resolution, alias swap, fallback, table validation."""

import copy
import json
from pathlib import Path

import pytest
from models_support import role_doc

from homelabnext.registry import ResolutionError
from homelabnext.registry.models import (
    ModelClient,
    RoleTable,
    RoleTableError,
    UnknownRole,
)

ROOT = Path(__file__).resolve().parents[2]


def ask(resolver):
    """A consumer: it names only the alias."""
    rm = resolver.resolve("mdl:main-reasoner")
    return ModelClient(rm).chat([{"role": "user", "content": "hi"}])


def test_resolves_alias_to_registry_backend(make_resolver, servers):
    rm = make_resolver().resolve("mdl:main-reasoner")
    assert rm.role == "main-reasoner" and rm.model_id == "example-27b"
    assert rm.backend == "inference-large" and rm.base_url == servers[0].url


def test_bare_and_prefixed_alias_are_equivalent(make_resolver):
    r = make_resolver()
    assert r.resolve("fast-classifier") == r.resolve("mdl:fast-classifier")


def test_alias_swap_leaves_consumer_unchanged(make_resolver):
    before = ask(make_resolver())
    swapped = role_doc(large_model="example-4b", large_backend="inference-small")
    after = ask(make_resolver(swapped))
    assert before.text == "large says hi" and after.text == "small says hi"
    assert (before.model, after.model) == ("example-27b", "example-4b")


def test_backend_without_dns_or_override_falls_back(make_resolver, servers):
    r = make_resolver()
    r.resolver.environ = {"HNX_ENDPOINT_INFERENCE_SMALL": servers[1].url}  # large has no endpoint
    rm = r.resolve("main-reasoner")
    assert rm.role == "fast-classifier" and rm.asked == "main-reasoner"
    assert any("falling back to mdl:fast-classifier" in t for t in rm.trail)


def test_nothing_resolves_raises_with_trail(make_resolver):
    r = make_resolver()
    r.resolver.environ = {}
    with pytest.raises(ResolutionError) as ei:
        r.resolve("main-reasoner")
    assert "falling back" in str(ei.value)


def test_binding_priority_orders_candidates(make_resolver, servers):
    doc = role_doc()
    doc["roles"]["main-reasoner"]["bindings"] = [
        {"backend": "svc:inference-large", "model_id": "example-27b", "priority": 5},
        {"backend": "svc:inference-small", "model_id": "example-4b", "priority": 1},
    ]
    assert make_resolver(doc).resolve("main-reasoner").backend == "inference-small"


def test_resolve_binding_reaches_each_binding_without_falling_back(make_resolver, servers):
    """The egress canary runs every binding of a role, not just the first that resolves."""
    doc = role_doc()
    large = doc["roles"]["main-reasoner"]["bindings"][0]
    small = dict(doc["roles"]["fast-classifier"]["bindings"][0], priority=1)
    doc["roles"]["main-reasoner"]["bindings"].append(small)
    r = make_resolver(doc)
    got = [r.resolve_binding("mdl:main-reasoner", b) for b in r.table.get("main-reasoner").bindings]
    assert [(m.model_id, m.base_url) for m in got] == [
        (large["model_id"], servers[0].url),
        (small["model_id"], servers[1].url),
    ]
    assert all(m.role == m.asked == "main-reasoner" and m.trail == () for m in got)
    r.resolver.environ = {"HNX_ENDPOINT_INFERENCE_SMALL": servers[1].url}
    with pytest.raises(ResolutionError):  # no fallback to another role
        r.resolve_binding("main-reasoner", r.table.get("main-reasoner").bindings[0])


def test_unknown_role(make_resolver):
    with pytest.raises(UnknownRole):
        make_resolver().resolve("mdl:no-such-role")
    with pytest.raises(UnknownRole):
        make_resolver().resolve("Not A Slug")


def test_unknown_backend_service_is_a_resolution_error(make_resolver):
    doc = role_doc(large_backend="not-in-registry")
    doc["roles"]["main-reasoner"].pop("fallback")
    with pytest.raises(ResolutionError):
        make_resolver(doc).resolve("main-reasoner")


def test_schema_example_loads():
    for name in ("model_roles.valid.json", "model_roles.embedder.json"):
        doc = json.loads((ROOT / "schemas/platform/examples" / name).read_text())
        assert RoleTable.from_dict(doc).roles


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (
            lambda d: d["roles"]["main-reasoner"]["bindings"][0].update(
                backend="http://backend.example.internal"
            ),
            "svc:",
        ),
        (lambda d: d["roles"]["main-reasoner"].update(fallback="mdl:ghost"), "unknown role"),
        (lambda d: d["roles"]["fast-classifier"].update(fallback="mdl:main-reasoner"), "loops"),
        (lambda d: d["roles"]["embedder"].update(kind="image"), "kind"),
        (lambda d: d["roles"]["embedder"].update(bindings=[]), "at least one binding"),
        # these used to escape as AttributeError / TypeError tracebacks, not RoleTableError
        (lambda d: d["roles"]["embedder"].update(bindings=["svc:x"]), r"bindings\[0\] must be"),
        (lambda d: d["roles"]["embedder"].update(bindings="svc:x"), "bindings must be a list"),
        (
            lambda d: d["roles"]["embedder"]["bindings"][0].update(priority="first"),
            "priority must be an integer",
        ),
        (
            lambda d: d["roles"]["embedder"].update(limits={"window_s": "60"}),
            "limits needs window_s",
        ),
        (lambda d: d["roles"]["embedder"].update(fallback=3), "fallback"),
        (lambda d: d["roles"]["embedder"].update(max_context_tokens="8k"), "max_context_tokens"),
        (lambda d: d["roles"]["embedder"].update(params=[1]), "params must be a mapping"),
        # a name with a trailing newline used to pass the slug check (``$`` matches before it)
        (lambda d: d["roles"].update({"embedder\n": d["roles"].pop("embedder")}), "slug"),
        (
            lambda d: d["roles"]["embedder"]["bindings"][0].update(backend="svc:inference-small\n"),
            "svc:",
        ),
    ],
)
def test_malformed_tables_are_refused(mutate, needle):
    doc = copy.deepcopy(role_doc())
    mutate(doc)
    with pytest.raises(RoleTableError, match=needle):
        RoleTable.from_dict(doc)


# --- through the gateway, and keyed backends (ADR-0007 decisions 2-3) ------------------------------
def _gateway_registry():
    import copy as _copy

    import yaml

    from homelabnext.registry.model import build_registry

    doc = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())
    for name, port in (("inference-large", 8001), ("inference-small", 8002), ("llm-gateway", 4000)):
        svc = _copy.deepcopy(doc["services"]["inference"])
        svc.update(capability=name, port=port)
        doc["services"][name] = svc
    return build_registry(doc)


def test_the_gateway_resolver_sends_the_role_and_the_callers_key():
    """A consumer reaches the gateway capability with the role as the model and its own key;
    without the key the gateway answers 401 (no backend is ever resolved)."""
    from conformance.fakes.openai_server import FakeOpenAIServer
    from homelabnext.registry import FakeDNS, Resolver
    from homelabnext.registry.models import GatewayResolver, ModelError

    gw = FakeOpenAIServer(
        models=["main-reasoner"], default_reply="via the gateway", api_keys=["sk-agent"]
    ).start()
    try:
        reg = _gateway_registry()
        res = Resolver(reg, dns=FakeDNS(), hosts={}, environ={"HNX_ENDPOINT_LLM_GATEWAY": gw.url})
        r = GatewayResolver(reg, RoleTable.from_dict(role_doc()), res)
        rm = r.resolve("mdl:main-reasoner")
        assert (rm.model_id, rm.backend, rm.base_url) == ("main-reasoner", "llm-gateway", gw.url)
        out = ModelClient(rm, api_key="sk-agent").chat([{"role": "user", "content": "hi"}])
        assert out.text == "via the gateway"
        with pytest.raises(ModelError) as ei:
            ModelClient(rm).chat([{"role": "user", "content": "hi"}])
        assert ei.value.status == 401
        with pytest.raises(UnknownRole):
            r.resolve("mdl:not-a-role")
        with pytest.raises(ResolutionError):
            r.resolve_binding("main-reasoner", r.table.get("main-reasoner").bindings[0])
    finally:
        gw.stop()


def test_the_k14_probe_carries_a_keyed_backends_key(registry):
    """A backend that requires its key (a serving engine with an API key) answers 401 to a keyless probe;
    the host-side probe passes the backend's own key."""
    from conformance.fakes.openai_server import FakeOpenAIServer
    from homelabnext.registry import FakeDNS, Resolver
    from homelabnext.registry.models import ModelResolver, probe

    model_id = RoleTable.from_dict(role_doc()).get("main-reasoner").bindings[0].model_id
    keyed = FakeOpenAIServer(models=[model_id], api_keys=["backend-key"]).start()
    try:
        env = {"HNX_ENDPOINT_INFERENCE_LARGE": keyed.url}
        res = Resolver(registry, dns=FakeDNS(), hosts={}, environ=env)
        rm = ModelResolver(registry, RoleTable.from_dict(role_doc()), res).resolve("main-reasoner")
        assert probe(rm).status == "error"
        assert probe(rm, api_key="backend-key").ok
    finally:
        keyed.stop()
