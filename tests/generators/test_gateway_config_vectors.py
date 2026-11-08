# SPDX-License-Identifier: Apache-2.0
"""The shared gateway config vectors say what the contract schema decides, and where the Go
gateway's reader deliberately decides otherwise.

``schemas/platform/gateway_config.schema.json`` is the gateway config contract; the Go gateway
reads the same file with a hand-written validator (``orchestrator/internal/gateway/validate.go``).
Nothing tied the two together, so ``conformance/fixtures/gateway_config_vectors.json`` does: each
vector is a whole config (an edit of the schema's ``local-and-cloud`` example), the ``schema``
verdict is computed here with the schema itself, and ``go`` is the verdict the Go reader must
give, which its test checks by parsing every vector.  The two verdicts may differ only where the
vector names the ``difference``, and every such difference is a rule of the reader the schema
cannot state (a cross-field rule, a higher minor version, the JSON number model), never a
looser check.  The Go test also parses every example and every negative of the schema in place.

To regenerate after a deliberate change: ``HNX_REGEN_GATEWAY_CONFIG_VECTORS=1 pytest`` on this
file.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from homelabnext.schema_registry import validator

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "conformance/fixtures/gateway_config_vectors.json"
BASE = ROOT / "schemas/platform/examples/gateway_config.local-and-cloud.json"
SCHEMA = validator("platform", "gateway_config.schema.json")

DEL = object()  #: an edit's value that deletes the key


def _role(name: str, *rest: Any) -> tuple:
    return ("roles", name, *rest)


def _dep(role: str, *rest: Any) -> tuple:
    return ("roles", role, "deployments", 0, *rest)


def _key(i: int, *rest: Any) -> tuple:
    return ("keys", i, *rest)


#: what the Go reader adds to the schema, each one named once and cited by its vectors
CROSS = "a cross-field rule of the reader the schema cannot state: "
DIFFERENCES = {
    "minor": "the reader serves any 1.x minor (a later minor only adds optional keys, which "
    "it still refuses when unknown); the 1.0 schema names only 1.0",
    "integer": "the reader decodes integer fields as Go int: an integer written with a "
    "fraction (8192.0) or beyond 64 bits is refused, which JSON Schema counts as an integer; "
    "the renderer writes integers without a fraction",
    "owner": CROSS + "a key's owner is profile:<id> or the key's own alias",
    "deployment-id": CROSS + "a deployment's id is <role>-<position>",
    "cloud-in-lab": CROSS + "a cloud deployment needs leaves_lab true on its role",
    "leaves-lab-ceiling": CROSS + "a role that leaves the lab has a tlp_ceiling of green or clear",
    "embedding-anthropic": CROSS + "an embedding role is never served by an anthropic deployment",
    "fallback": CROSS + "a fallback is another role of the same kind, and an in-lab role does "
    "not fall back to one that leaves the lab",
    "max-cost": CROSS + "a role's max_cost needs its cost_per_1k_tokens",
    "keys-order": CROSS + "keys are sorted by alias and each alias is declared once",
    "env-reuse": CROSS + "every environment name serves one principal",
    "key-roles": CROSS + "a key's roles are sorted roles of the config, include every fallback "
    "of each, and a local-only key lists none that leaves the lab",
}

#: (name, edits, go verdict, difference id or None); each edit is (path, value), DEL deletes
EDITS: list[tuple[str, list[tuple[tuple, Any]], str, str | None]] = [
    ("example", [], "accept", None),
    # -- both accept
    ("name-empty", [(("name",), "")], "accept", None),
    ("name-64", [(("name",), "a" * 64)], "accept", None),
    ("no-telemetry-reader", [(("telemetry_reader",), None)], "accept", None),
    ("conformance-only-true", [(("conformance_only",), True)], "accept", None),
    ("conformance-only-false", [(("conformance_only",), False)], "accept", None),
    ("max-context-tokens-1", [(_role("embedder", "max_context_tokens"), 1)], "accept", None),
    ("cost-zero", [(_role("embedder", "cost_per_1k_tokens"), 0)], "accept", None),
    ("max-cost-integer", [(_role("cloud-reasoner", "limits", "max_cost"), 3)], "accept", None),
    ("limits-of-one", [(_role("small-local", "limits"),
                        {"window_s": 1, "max_requests": 1, "max_tokens": 1, "max_cost": None})],
     "accept", None),
    ("base-url-address-and-port", [(_dep("embedder", "base_url"), "http://127.0.0.1:9999")],  # no-raw-endpoint: allow a contract vector, never dialled
     "accept", None),
    ("model-with-tag", [(_dep("embedder", "model"), "Org/model-1.5:q4_K")], "accept", None),
    ("model-128", [(_dep("embedder", "model"), "m" * 128)], "accept", None),
    ("backend-64", [(_dep("embedder", "backend"), "b" * 64)], "accept", None),
    ("owner-profile", [(_key(0, "owner"), "profile:ops-team")], "accept", None),
    ("owner-profile-128", [(_key(0, "owner"), "profile:" + "o" * 120)], "accept", None),
    ("base-url-256", [(_dep("embedder", "base_url"), "http://" + "h" * 249)], "accept", None),
    ("telemetry-key-env-128", [(("telemetry_reader", "key_env"), "HNX_SECRET_" + "T" * 117)],
     "accept", None),
    ("env-128", [(("admin_key_env",), "HNX_SECRET_" + "A" * 117)], "accept", None),
    ("no-keys", [(("keys",), [])], "accept", None),
    # -- both refuse
    ("version-2", [(("version",), "2.0")], "refuse", None),
    ("version-major-only", [(("version",), "1")], "refuse", None),
    ("version-number", [(("version",), 1.0)], "refuse", None),
    ("extra-field", [(("router",), {})], "refuse", None),
    ("missing-keys", [(("keys",), DEL)], "refuse", None),
    ("missing-name", [(("name",), DEL)], "refuse", None),
    ("name-not-slug", [(("name",), "Bad_Name")], "refuse", None),
    ("name-trailing-newline", [(("name",), "lab\n")], "refuse", None),
    ("name-65", [(("name",), "a" * 65)], "refuse", None),
    ("name-null", [(("name",), None)], "refuse", None),
    ("admin-env-not-secret", [(("admin_key_env",), "MASTER_KEY")], "refuse", None),
    ("env-129", [(("admin_key_env",), "HNX_SECRET_" + "A" * 118)], "refuse", None),
    ("keys-null", [(("keys",), None)], "refuse", None),
    ("roles-empty", [(("roles",), {}), (("keys",), [])], "refuse", None),
    ("roles-null", [(("roles",), None), (("keys",), [])], "refuse", None),
    ("role-null", [(_role("embedder"), None)], "refuse", None),
    ("role-alias-not-slug", [(("roles", "Embedder"), "@embedder")], "refuse", None),
    ("role-alias-65", [(("roles", "e" * 65), "@embedder")], "refuse", None),
    ("role-extra-field", [(_role("embedder", "weight"), 1)], "refuse", None),
    ("role-missing-fallbacks", [(_role("embedder", "fallbacks"), DEL)], "refuse", None),
    ("kind-unknown", [(_role("embedder", "kind"), "completion")], "refuse", None),
    ("max-context-tokens-0", [(_role("embedder", "max_context_tokens"), 0)], "refuse", None),
    ("tlp-ceiling-not-canonical", [(_role("embedder", "tlp_ceiling"), "TLP:RED")], "refuse", None),
    ("leaves-lab-null", [(_role("embedder", "leaves_lab"), None)], "refuse", None),
    ("leaves-lab-string", [(_role("embedder", "leaves_lab"), "false")], "refuse", None),
    ("deployments-empty", [(_role("embedder", "deployments"), [])], "refuse", None),
    ("deployment-null", [(_dep("embedder"), None)], "refuse", None),
    ("fallbacks-null", [(_role("embedder", "fallbacks"), None)], "refuse", None),
    ("fallbacks-twice", [(_role("agent-local", "fallbacks"), ["small-local", "small-local"])],
     "refuse", None),
    ("role-limits-window-0", [(_role("small-local", "limits", "window_s"), 0)], "refuse", None),
    ("role-limits-no-window", [(_role("small-local", "limits", "window_s"), DEL)], "refuse", None),
    ("role-max-requests-0", [(_role("small-local", "limits", "max_requests"), 0)], "refuse", None),
    ("role-max-tokens-0", [(_role("small-local", "limits", "max_tokens"), 0)], "refuse", None),
    ("role-max-requests-negative", [(_role("small-local", "limits", "max_requests"), -1)],
     "refuse", None),
    ("role-max-cost-0", [(_role("cloud-reasoner", "limits", "max_cost"), 0)], "refuse", None),
    ("role-max-cost-negative", [(_role("cloud-reasoner", "limits", "max_cost"), -0.5)],
     "refuse", None),
    ("cost-negative", [(_role("embedder", "cost_per_1k_tokens"), -1)], "refuse", None),
    ("deployment-extra-field", [(_dep("embedder", "rpm"), 1)], "refuse", None),
    ("deployment-missing-api-key-env", [(_dep("embedder", "api_key_env"), DEL)], "refuse", None),
    ("deployment-id-not-slug", [(_dep("embedder", "id"), "Embedder-1")], "refuse", None),
    ("backend-empty", [(_dep("embedder", "backend"), "")], "refuse", None),
    ("backend-not-slug", [(_dep("embedder", "backend"), "infer_b")], "refuse", None),
    ("backend-65", [(_dep("embedder", "backend"), "b" * 65)], "refuse", None),
    ("locality-unknown", [(_dep("embedder", "locality"), "edge")], "refuse", None),
    ("protocol-unknown", [(_dep("embedder", "protocol"), "gemini")], "refuse", None),
    ("base-url-path", [(_dep("embedder", "base_url"), "http://h.example/v1")], "refuse", None),
    ("base-url-slash", [(_dep("embedder", "base_url"), "http://h.example/")], "refuse", None),
    ("base-url-scheme", [(_dep("embedder", "base_url"), "ftp://h.example")], "refuse", None),
    ("base-url-userinfo", [(_dep("embedder", "base_url"), "http://u:p@h.example")], "refuse", None),
    ("base-url-query", [(_dep("embedder", "base_url"), "http://h.example?x=1")], "refuse", None),
    ("base-url-upper-case", [(_dep("embedder", "base_url"), "http://H.example:8000")],  # no-raw-endpoint: allow a contract vector, never dialled
     "refuse", None),
    ("base-url-ipv6", [(_dep("embedder", "base_url"), "http://[::1]:8000")], "refuse", None),  # no-raw-endpoint: allow a contract vector, never dialled
    ("base-url-underscore", [(_dep("embedder", "base_url"), "http://h_1.example")], "refuse", None),
    ("base-url-port-6-digits", [(_dep("embedder", "base_url"), "http://h.example:123456")],
     "refuse", None),
    ("base-url-empty-port", [(_dep("embedder", "base_url"), "http://h.example:")], "refuse", None),
    ("base-url-trailing-dot", [(_dep("embedder", "base_url"), "http://h.example.")], "refuse", None),
    ("base-url-257", [(_dep("embedder", "base_url"), "http://" + "h" * 250)], "refuse", None),
    ("model-empty", [(_dep("embedder", "model"), "")], "refuse", None),
    ("model-space", [(_dep("embedder", "model"), "small model")], "refuse", None),
    ("model-non-ascii", [(_dep("embedder", "model"), "mod\u00e8le")], "refuse", None),
    ("model-129", [(_dep("embedder", "model"), "m" * 129)], "refuse", None),
    ("api-key-env-is-a-value", [(_dep("cloud-reasoner", "api_key_env"), "sk-live-123")],
     "refuse", None),
    ("key-null", [(_key(0), None)], "refuse", None),
    ("key-extra-field", [(_key(0, "models"), [])], "refuse", None),
    ("key-alias-not-slug", [(_key(0, "alias"), "Cloud-Tool"), (_key(0, "owner"), "Cloud-Tool")],
     "refuse", None),
    ("key-alias-65", [(_key(0, "alias"), "c" * 65), (_key(0, "owner"), "c" * 65)],
     "refuse", None),
    ("key-env-not-secret", [(_key(0, "key_env"), "CLOUD_TOOL")], "refuse", None),
    ("owner-profile-not-slug", [(_key(0, "owner"), "profile:Ops.Team")], "refuse", None),
    ("owner-profile-empty", [(_key(0, "owner"), "profile:")], "refuse", None),
    ("owner-profile-129", [(_key(0, "owner"), "profile:" + "o" * 121)], "refuse", None),
    ("telemetry-key-env-129", [(("telemetry_reader", "key_env"), "HNX_SECRET_" + "T" * 118)],
     "refuse", None),
    ("data-tier-unknown", [(_key(0, "data_tier"), "any")], "refuse", None),
    ("key-tlp-not-canonical", [(_key(0, "tlp_ceiling"), "white")], "refuse", None),
    ("key-roles-null", [(_key(0, "roles"), None)], "refuse", None),
    ("key-roles-twice", [(_key(0, "roles"), ["cloud-reasoner", "cloud-reasoner"])],
     "refuse", None),
    ("key-limits-max-cost", [(_key(0, "limits", "max_cost"), 1)], "refuse", None),
    ("key-max-requests-0", [(_key(0, "limits", "max_requests"), 0)], "refuse", None),
    ("key-limits-window-0", [(_key(0, "limits", "window_s"), 0)], "refuse", None),
    ("telemetry-reader-extra-field", [(("telemetry_reader", "role"), "x")], "refuse", None),
    ("telemetry-key-env-not-secret", [(("telemetry_reader", "key_env"), "READER")],
     "refuse", None),
    ("conformance-only-string", [(("conformance_only",), "yes")], "refuse", None),
    ("conformance-only-null", [(("conformance_only",), None)], "refuse", None),
    # -- the reader's own rules: the schema accepts, Go refuses (or, for the minor, the reverse)
    ("version-later-minor", [(("version",), "1.7")], "accept", "minor"),
    ("max-context-tokens-with-fraction", [(_role("embedder", "max_context_tokens"), 8192.0)],
     "refuse", "integer"),
    ("max-tokens-beyond-64-bits", [(_role("small-local", "limits", "max_tokens"), 2**63)],
     "refuse", "integer"),
    ("owner-another-slug", [(_key(0, "owner"), "someone-else")], "refuse", "owner"),
    ("deployment-id-wrong-position", [(_dep("embedder", "id"), "embedder-2")],
     "refuse", "deployment-id"),
    ("deployment-id-other-role", [(_dep("embedder", "id"), "small-local-1")],
     "refuse", "deployment-id"),
    ("cloud-deployment-in-lab", [(_role("cloud-reasoner", "leaves_lab"), False)],
     "refuse", "cloud-in-lab"),
    ("leaves-lab-at-red", [(_role("cloud-reasoner", "tlp_ceiling"), "red")],
     "refuse", "leaves-lab-ceiling"),
    ("leaves-lab-at-amber", [(_role("cloud-reasoner", "tlp_ceiling"), "amber")],
     "refuse", "leaves-lab-ceiling"),
    ("embedding-on-anthropic", [(_dep("embedder", "protocol"), "anthropic")],
     "refuse", "embedding-anthropic"),
    ("fallback-itself", [(_role("embedder", "fallbacks"), ["embedder"])], "refuse", "fallback"),
    ("fallback-unknown", [(_role("embedder", "fallbacks"), ["nowhere"])], "refuse", "fallback"),
    ("fallback-other-kind", [(_role("embedder", "fallbacks"), ["small-local"])],
     "refuse", "fallback"),
    ("fallback-leaves-lab", [(_role("small-local", "fallbacks"), ["cloud-reasoner"])],
     "refuse", "fallback"),
    ("max-cost-without-cost", [(_role("cloud-reasoner", "cost_per_1k_tokens"), None)],
     "refuse", "max-cost"),
    ("keys-unsorted", [(("keys",), "@keys-reversed")], "refuse", "keys-order"),
    ("key-alias-twice", [(_key(1, "alias"), "cloud-tool"), (_key(1, "owner"), "cloud-tool")],
     "refuse", "keys-order"),
    ("key-env-reused", [(_key(1, "key_env"), "HNX_SECRET_LLM_GATEWAY_KEY_CLOUD_TOOL")],
     "refuse", "env-reuse"),
    ("key-env-is-admin-env", [(_key(1, "key_env"), "HNX_SECRET_LLM_GATEWAY_MASTER_KEY")],
     "refuse", "env-reuse"),
    ("key-env-is-telemetry-env", [(_key(1, "key_env"),
                                   "HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER")],
     "refuse", "env-reuse"),
    ("provider-env-is-a-key-env", [(_dep("cloud-reasoner", "api_key_env"),
                                    "HNX_SECRET_LLM_GATEWAY_KEY_CLOUD_TOOL")],
     "refuse", "env-reuse"),
    ("key-role-not-a-role", [(_key(1, "roles"), ["agent-local", "small-local", "zz"])],
     "refuse", "key-roles"),
    ("key-roles-unsorted", [(_key(1, "roles"), ["small-local", "agent-local"])],
     "refuse", "key-roles"),
    ("key-misses-a-fallback", [(_key(1, "roles"), ["agent-local"])], "refuse", "key-roles"),
    ("local-only-key-on-leaves-lab-role", [(_key(1, "roles"),
                                            ["agent-local", "cloud-reasoner", "small-local"])],
     "refuse", "key-roles"),
]  # fmt: skip


def _apply(cfg: dict, path: tuple, value: Any) -> None:
    *parent, last = path
    node: Any = cfg
    for step in parent:
        node = node[step]
    if value is DEL:
        del node[last]
    elif value == "@keys-reversed":
        node[last] = list(reversed(node[last]))
    elif isinstance(value, str) and value.startswith("@"):
        # rename a role (its alias is the key) and its deployments' ids with it, so the new
        # alias is the only thing the vector changes
        role = node[last] = node.pop(value[1:])
        for i, d in enumerate(role["deployments"]):
            d["id"] = f"{last}-{i + 1}"
    else:
        node[last] = copy.deepcopy(value)


def build() -> dict:
    base = json.loads(BASE.read_text(encoding="utf-8"))
    vectors = []
    for name, edits, go, difference in EDITS:
        cfg = copy.deepcopy(base)
        for path, value in edits:
            _apply(cfg, path, value)
        schema = "accept" if SCHEMA.is_valid(cfg) else "refuse"
        vectors.append(
            {"name": name, "schema": schema, "go": go, "difference": difference, "config": cfg}
        )
    return {
        "description": (
            "Test vectors for the gateway config contract, generated by "
            "tests/generators/test_gateway_config_vectors.py: each config is an edit of "
            "schemas/platform/examples/gateway_config.local-and-cloud.json, `schema` is what "
            "schemas/platform/gateway_config.schema.json decides and `go` is what the Go "
            "gateway's reader (orchestrator/internal/gateway) must decide. They differ only "
            "where `difference` names an entry of `differences`. Not representable here, and "
            "tested by the Go side alone: a key that appears twice or in another case, which "
            "the reader refuses and a JSON object cannot hold."
        ),
        "differences": DIFFERENCES,
        "vectors": vectors,
    }


def _text() -> str:
    return json.dumps(build(), indent=1, ensure_ascii=True) + "\n"


def test_the_vectors_file_is_what_the_schema_says():
    if os.environ.get("HNX_REGEN_GATEWAY_CONFIG_VECTORS") == "1":
        VECTORS.write_text(_text(), encoding="utf-8")
    assert VECTORS.read_text(encoding="utf-8") == _text(), (
        "conformance/fixtures/gateway_config_vectors.json is stale: rerun this test with "
        "HNX_REGEN_GATEWAY_CONFIG_VECTORS=1 after a deliberate change to the schema, its "
        "example or the vectors"
    )


def test_the_verdicts_differ_only_where_a_difference_is_named():
    for v in build()["vectors"]:
        if v["difference"] is None:
            assert v["go"] == v["schema"], f"{v['name']}: the reader and the schema disagree"
        else:
            assert v["go"] != v["schema"], f"{v['name']}: names a difference that is not one"
            assert v["difference"] in DIFFERENCES


def test_every_difference_is_used_and_only_the_minor_widens():
    vs = build()["vectors"]
    assert {v["difference"] for v in vs} - {None} == set(DIFFERENCES)
    wider = {v["difference"] for v in vs if v["go"] == "accept" and v["schema"] == "refuse"}
    assert wider == {"minor"}, "the reader is looser than the schema only on the minor version"


def test_the_vectors_are_named_once_and_cover_both_verdicts():
    vs = build()["vectors"]
    assert len({v["name"] for v in vs}) == len(vs)
    assert {(v["schema"], v["go"]) for v in vs} == {
        ("accept", "accept"), ("refuse", "refuse"), ("accept", "refuse"), ("refuse", "accept"),
    }  # fmt: skip
