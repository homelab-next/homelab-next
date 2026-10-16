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
    ],
)
def test_malformed_tables_are_refused(mutate, needle):
    doc = copy.deepcopy(role_doc())
    mutate(doc)
    with pytest.raises(RoleTableError, match=needle):
        RoleTable.from_dict(doc)
