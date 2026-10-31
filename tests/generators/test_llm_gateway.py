# SPDX-License-Identifier: Apache-2.0
"""LLM gateway config generator: render, the locality rule, the audit of rendered files, the CLI
drift check and LiteLLM key provisioning (against a stdlib fake; no network)."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

from homelabnext.cli import main as hnx
from homelabnext.generators import llm_gateway as gw

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "compose" / "lab-in-a-box" / "config" / "llm-gateway"
LAB_SPEC = LAB / "gateway.yml"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only

ROLES = {
    "version": 1,
    "roles": {
        "agent-local": {
            "tier": "large",
            "bindings": [{"backend": "svc:infer-a", "model_id": "example-27b"}],
            "fallback": "mdl:small-local",
        },
        "small-local": {
            "tier": "fast",
            "bindings": [{"backend": "svc:infer-b", "model_id": "example-4b"}],
            "limits": {"window_s": 3600, "max_requests": 120},
        },
        "cloud-reasoner": {
            "tier": "large",
            "bindings": [{"backend": "svc:cloud", "model_id": "example-cloud-1"}],
        },
    },
}


def spec_doc(**over):
    doc = {
        "roles": "roles.json",
        "master_key": "secret:llm-gateway/master-key",
        "database_url": "secret:llm-gateway/database-url",
        "backends": {
            "svc:infer-a": {"locality": "local", "port": 8000},
            "svc:infer-b": {"locality": "local", "port": 8000},
            "svc:cloud": {
                "locality": "cloud",
                "provider": "anthropic",
                "api_key": "secret:llm-gateway/anthropic-api-key",
            },
        },
        "keys": [
            {
                "name": "local-agent",
                "key": "secret:llm-gateway/key-local-agent",
                "roles": ["mdl:agent-local"],
                "data_tier": "local-only",
            },
            {
                "name": "cloud-tool",
                "key": "secret:llm-gateway/key-cloud-tool",
                "roles": ["mdl:cloud-reasoner"],
                "data_tier": "cloud-allowed",
                "limits": {"window_s": 60, "max_requests": 10},
            },
        ],
    }
    doc.update(over)
    return doc


def make_spec(tmp_path, roles=None, **over):
    (tmp_path / "roles.json").write_text(json.dumps(roles or ROLES))
    path = tmp_path / "gateway.yml"
    path.write_text(yaml.safe_dump(spec_doc(**over)))
    return path


# --- render --------------------------------------------------------------------------------------


def test_render_both_gateways_from_one_spec(tmp_path):
    files = gw.render_file(make_spec(tmp_path))
    assert sorted(files) == [
        "bifrost/config.json",
        "bifrost/model-parameters.json",
        "bifrost/pricing.json",
        "litellm/config.yaml",
        "litellm/keys.json",
    ]
    lt = yaml.safe_load(files["litellm/config.yaml"])
    names = {d["model_name"]: d["litellm_params"] for d in lt["model_list"]}
    assert sorted(names) == ["agent-local", "cloud-reasoner", "small-local"]  # role = alias
    assert names["agent-local"]["model"] == "openai/example-27b"
    want = "http://infer-a.svc.example.internal:8000/v1"  # no-raw-endpoint: allow rendered alias
    assert names["agent-local"]["api_base"] == want
    assert names["cloud-reasoner"]["model"] == "anthropic/example-cloud-1"
    assert names["small-local"]["rpm"] == 2  # 120 per hour, as a per-minute share rounded down
    assert lt["router_settings"]["fallbacks"] == [{"agent-local": ["small-local"]}]
    assert lt["router_settings"]["enable_pre_call_checks"] is True
    assert lt["general_settings"]["database_url"].startswith("os.environ/HNX_SECRET_")
    keys = {k["key_alias"]: k for k in json.loads(files["litellm/keys.json"])["keys"]}
    assert keys["local-agent"]["models"] == ["agent-local", "small-local"]
    assert keys["cloud-tool"]["rpm_limit"] == 10
    assert keys["local-agent"]["key_env"] == "HNX_SECRET_LLM_GATEWAY_KEY_LOCAL_AGENT"


def test_bifrost_serves_roles_as_key_aliases_and_routes_the_fallback(tmp_path):
    doc = json.loads(gw.render_file(make_spec(tmp_path))["bifrost/config.json"])
    prov = doc["providers"]["hnx-infer-a"]
    assert prov["keys"][0]["aliases"] == {"agent-local": "example-27b"}
    want = "http://infer-a.svc.example.internal:8000"  # no-raw-endpoint: allow rendered alias
    assert prov["network_config"]["base_url"] == want
    assert prov["custom_provider_config"] == {"base_provider_type": "openai"}
    gov = doc["governance"]
    (rule,) = gov["routing_rules"]
    assert rule["cel_expression"] == "model == 'agent-local'"  # Bifrost's CEL names it `model`
    assert rule["fallbacks"] == ["hnx-infer-b/small-local"]
    vks = {v["name"]: v for v in gov["virtual_keys"]}
    assert {p["provider"] for p in vks["local-agent"]["provider_configs"]} == {
        "hnx-infer-a",
        "hnx-infer-b",
    }
    assert vks["cloud-tool"]["value"] == "env.HNX_SECRET_LLM_GATEWAY_KEY_CLOUD_TOOL"
    rl = {r["id"]: r for r in gov["rate_limits"]}
    assert rl["rl-role-small-local"]["request_reset_duration"] == "1h"
    assert doc["framework"]["pricing"]["pricing_url"] == "file:///app/data/pricing.json"


def test_render_is_deterministic(tmp_path):
    p = make_spec(tmp_path)
    assert gw.render_file(p) == gw.render_file(p)


def test_no_secret_value_or_literal_in_the_output(tmp_path):
    text = "".join(gw.render_file(make_spec(tmp_path)).values())
    assert "secret:" not in text  # references are mapped to their environment variables


def test_agent_profiles_become_one_key_each_and_their_tier_binds_the_role():
    spec = gw.load_spec(LAB_SPEC)
    by_owner = {k.owner: k for k in spec.keys if k.owner}
    assert set(by_owner) == {"profile:responder", "profile:reader"}
    assert by_owner["profile:reader"].secret == "secret:llm-gateway/key-reader"
    assert spec.local_only["main-reasoner"] == "profile:responder is data_tier local-only"


# --- the locality rule: fails on a bad input, passes on the examples ----------------------------


def test_the_lab_spec_and_its_committed_output_pass():
    assert hnx(["gen", "gateway", "render", str(LAB_SPEC), str(LAB), "--check"]) == 0


def test_local_only_role_falling_back_to_cloud_is_refused(tmp_path):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["agent-local"]["fallback"] = "mdl:cloud-reasoner"
    with pytest.raises(gw.GatewaySpecError) as ei:
        gw.render_file(make_spec(tmp_path, roles))
    msg = str(ei.value)
    assert "mdl:agent-local is local-only (key local-agent is data_tier local-only)" in msg
    assert "falls back to mdl:cloud-reasoner, which binds cloud backend svc:cloud" in msg


def test_local_only_role_bound_to_cloud_is_refused(tmp_path):
    keys = spec_doc()["keys"] + [
        {
            "name": "private",
            "key": "secret:llm-gateway/key-private",
            "roles": ["mdl:cloud-reasoner"],
            "data_tier": "local-only",
        }
    ]
    with pytest.raises(gw.GatewaySpecError, match="binds cloud backend svc:cloud"):
        gw.render_file(make_spec(tmp_path, keys=keys))


def test_an_agent_role_may_not_fall_back_across_providers_even_cloud_allowed(tmp_path):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["cloud-reasoner"]["fallback"] = "mdl:small-local"
    prof = {
        "id": "profile:researcher",
        "model_role": "mdl:cloud-reasoner",
        "data_tier": "cloud-allowed",
    }
    (tmp_path / "profile.researcher.json").write_text(json.dumps(prof))
    with pytest.raises(gw.GatewaySpecError, match="falls back across providers to mdl:small-local"):
        gw.render_file(make_spec(tmp_path, roles, profiles=["profile.*.json"]))


def test_a_non_agent_cloud_role_may_fall_back_to_local(tmp_path):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["cloud-reasoner"]["fallback"] = "mdl:small-local"
    files = gw.render_file(make_spec(tmp_path, roles))  # cloud-tool is no agent: allowed
    lt = yaml.safe_load(files["litellm/config.yaml"])
    assert {"cloud-reasoner": ["small-local"]} in lt["router_settings"]["fallbacks"]


@pytest.mark.parametrize(
    "over, words",
    [
        ({"master_key": "sk-fake-literal-master-key"}, "master_key: must be a secret:"),
        ({"backends": {"svc:infer-a": {"locality": "local", "port": 8000}}}, "backends does not"),
        ({"local_only": ["not-a-role"]}, "is not an mdl: role id"),
        ({"surprise": 1}, "unknown key 'surprise'"),
        ({"database_url": "secret:db\nx"}, "control characters"),
    ],
)
def test_spec_errors_are_reported(tmp_path, over, words):
    with pytest.raises(gw.GatewaySpecError, match=words):
        gw.render_file(make_spec(tmp_path, **over))


# --- locality is where a backend is, not what the spec calls it ---------------------------------

SELF_DECLARED = {"locality": "local", "host": "api.example.com", "port": 443, "scheme": "https"}


def test_a_self_declared_local_backend_is_refused(tmp_path):
    backends = spec_doc()["backends"] | {"svc:infer-a": SELF_DECLARED}
    with pytest.raises(gw.GatewaySpecError) as ei:
        gw.render_file(make_spec(tmp_path, backends=backends))
    assert "backends.svc:infer-a: locality local is not self-declared: api.example.com" in str(
        ei.value
    )


def test_a_local_host_under_the_service_domain_is_accepted(tmp_path):
    host = {"locality": "local", "host": "gpu-box.svc.example.internal", "port": 8000}
    files = gw.render_file(
        make_spec(tmp_path, backends=spec_doc()["backends"] | {"svc:infer-a": host})
    )
    lt = yaml.safe_load(files["litellm/config.yaml"])
    bases = {d["litellm_params"].get("api_base") for d in lt["model_list"]}
    assert "http://gpu-box.svc.example.internal:8000/v1" in bases  # no-raw-endpoint: allow alias


def registry_with(tmp_path, zone_name):
    doc = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())
    doc["zones"][zone_name] = doc["zones"].pop("compute")
    for h in doc["hosts"].values():
        if h["zone"] == "compute":
            h["zone"] = zone_name
    for s in doc["services"].values():
        s["clients"] = [zone_name if c == "compute" else c for c in s.get("clients", [])]
    (tmp_path / "registry.yml").write_text(yaml.safe_dump(doc))
    return "registry.yml"


def test_a_registry_service_in_a_cloud_zone_is_not_local(tmp_path):
    backends = spec_doc()["backends"] | {"svc:inference": {"locality": "local"}}
    roles = copy.deepcopy(ROLES)
    roles["roles"]["agent-local"]["bindings"][0]["backend"] = "svc:inference"
    reg = registry_with(tmp_path, "cloud")
    with pytest.raises(
        gw.GatewaySpecError, match="registry service inference is not in a lab zone"
    ):
        gw.render_file(make_spec(tmp_path, roles, registry=reg, backends=backends))
    reg = registry_with(tmp_path, "compute")
    files = gw.render_file(make_spec(tmp_path, roles, registry=reg, backends=backends))
    assert "inference.svc.example.internal" in files["litellm/config.yaml"]


def test_a_cloud_api_domain_named_as_the_lab_domain_is_refused(tmp_path):
    # the spec's own domain cannot make a provider's API internal (review of #32)
    host = {"locality": "local", "host": "x.api.anthropic.com", "port": 443, "scheme": "https"}
    backends = spec_doc()["backends"] | {"svc:infer-a": host}
    with pytest.raises(gw.GatewaySpecError, match="under a model provider's API domain"):
        gw.render_file(
            make_spec(tmp_path, backends=backends, domain="anthropic.com", svc_label="api")
        )


def test_audit_counts_a_host_under_a_cloud_api_domain_as_cloud(tmp_path):
    spec = dataclasses.replace(
        gw.load_spec(make_spec(tmp_path)), service_domain="api.anthropic.com"
    )
    assert not gw.internal_host(spec, "x.api.anthropic.com")


def test_a_spec_domain_that_differs_from_the_registry_is_refused(tmp_path):
    reg = registry_with(tmp_path, "compute")
    with pytest.raises(gw.GatewaySpecError, match="differs from the registry's"):
        gw.render_file(make_spec(tmp_path, registry=reg, domain="elsewhere.example"))


def test_audit_refuses_a_self_declared_local_backend():
    spec, files = lab_files()
    bad = dataclasses.replace(spec.backends["inference-small"], host="api.example.com", port=443)
    spec.backends["inference-small"] = bad
    doc = yaml.safe_load(files["litellm/config.yaml"])
    for d in doc["model_list"]:
        if d["model_name"] == "fast-classifier":
            url = "https://api.example.com:443/v1"  # no-raw-endpoint: allow a cloud host in a test
            d["litellm_params"]["api_base"] = url
    files["litellm/config.yaml"] = yaml.safe_dump(doc)
    problems = "\n".join(gw.audit(files, spec))
    assert "backend svc:inference-small is declared local but api.example.com" in problems
    assert (
        "fast-classifier (profile:reader is data_tier local-only) has a cloud deployment"
        in problems
    )


# --- one Bifrost provider per backend, one model per role and provider ---------------------------


def test_two_cloud_backends_of_one_provider_are_refused(tmp_path):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["second-cloud"] = {
        "tier": "large",
        "bindings": [{"backend": "svc:cloud-b", "model_id": "example-cloud-2"}],
    }
    backends = spec_doc()["backends"] | {
        "svc:cloud-b": {
            "locality": "cloud",
            "provider": "anthropic",
            "api_key": "secret:llm-gateway/anthropic-team-b",
        }
    }
    with pytest.raises(gw.GatewaySpecError, match="svc:cloud, svc:cloud-b are all provider"):
        gw.render_file(make_spec(tmp_path, roles, backends=backends))


def test_a_role_bound_twice_on_one_provider_is_refused(tmp_path):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["small-local"]["bindings"].append(
        {"backend": "svc:infer-b", "model_id": "example-4b-alt"}
    )
    with pytest.raises(gw.GatewaySpecError, match="mdl:small-local: two bindings on provider"):
        gw.render_file(make_spec(tmp_path, roles))


# --- one secret, one credential ------------------------------------------------------------------


def with_extra_key(ref):
    return spec_doc()["keys"] + [
        {"name": "batch", "key": ref, "roles": ["mdl:cloud-reasoner"], "data_tier": "cloud-allowed"}
    ]


@pytest.mark.parametrize(
    "over, words",
    [
        # distinct references, one environment variable: HNX_SECRET_LLM_GATEWAY_KEY_LOCAL_AGENT
        (
            {"keys": with_extra_key("secret:llm-gateway/key.local-agent")},
            "are all delivered in HNX_SECRET_LLM_GATEWAY_KEY_LOCAL_AGENT",
        ),
        (
            {"keys": with_extra_key("secret:llm-gateway/key-local-agent")},
            "key local-agent and key batch use the same secret secret:llm-gateway/key-local-agent",
        ),
        (
            {"keys": with_extra_key("secret:llm-gateway/master-key")},
            "key batch and master_key use the same secret",
        ),
        (
            {"keys": with_extra_key("secret:llm-gateway/database_url")},
            "are all delivered in HNX_SECRET_LLM_GATEWAY_DATABASE_URL",
        ),
        (
            {"keys": with_extra_key("secret:llm-gateway/anthropic-api-key")},
            "the upstream key of backend svc:cloud",
        ),
        ({"database_url": "secret:llm-gateway/master-key"}, "master_key and database_url use"),
    ],
)
def test_a_secret_serves_exactly_one_credential(tmp_path, over, words):
    with pytest.raises(gw.GatewaySpecError) as ei:
        gw.render_file(make_spec(tmp_path, **over))
    assert words in str(ei.value)


def test_an_agent_profile_key_may_not_be_reused_by_a_spec_key():
    doc = yaml.safe_load(LAB_SPEC.read_text())
    doc["keys"].append(
        {
            "name": "cloud-batch",
            "key": "secret:llm-gateway/key.reader",  # the reader agent's variable
            "roles": ["mdl:main-reasoner"],
            "data_tier": "cloud-allowed",
        }
    )
    with pytest.raises(gw.GatewaySpecError, match="HNX_SECRET_LLM_GATEWAY_KEY_READER"):
        gw.spec_from_dict(doc, base=LAB_SPEC.parent)


# --- limits are enforced as declared or tighter, never looser -----------------------------------


def with_limits(limits):
    keys = spec_doc()["keys"]
    keys[1] = dict(keys[1], limits=limits)
    return keys


@pytest.mark.parametrize(
    "limits, words",
    [
        ({"window_s": 3600, "max_requests": 0}, "0 would read as unlimited"),
        ({"window_s": 3600, "max_requests": 1}, "cannot be a per-minute limit"),  # was 1 rpm
        ({"window_s": 10, "max_requests": 5}, "cannot be a per-minute limit"),  # was 30 rpm
        ({"window_s": 90, "max_requests": 3}, "cannot be a per-minute limit"),
        ({"window_s": 60, "max_requests": "3"}, "must be a whole number"),
        ({"window_s": 60, "max_requests": 2.5}, "must be a whole number"),
        ({"window_s": 60, "max_tokens": True}, "must be a whole number"),
        ({"window_s": 0.5, "max_requests": 3}, "window_s must be a whole number of seconds"),
        ({"window_s": 60}, "limits needs max_requests, max_tokens or max_cost"),
    ],
)
def test_a_key_limit_that_would_render_looser_is_refused(tmp_path, limits, words):
    with pytest.raises(gw.GatewaySpecError, match=words):
        gw.render_file(make_spec(tmp_path, keys=with_limits(limits)))


def test_a_role_limit_that_would_render_looser_is_refused(tmp_path):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["small-local"]["limits"] = {"window_s": 3600, "max_requests": 1}
    with pytest.raises(gw.GatewaySpecError, match=r"mdl:small-local: limits\.max_requests 1 per"):
        gw.render_file(make_spec(tmp_path, roles))


def test_a_whole_minute_window_renders_its_exact_or_tighter_share(tmp_path):
    files = gw.render_file(
        make_spec(tmp_path, keys=with_limits({"window_s": 600, "max_requests": 25}))
    )
    keys = {k["key_alias"]: k for k in json.loads(files["litellm/keys.json"])["keys"]}
    assert keys["cloud-tool"]["rpm_limit"] == 2  # 25 per 10 min: 2 a minute, never 3
    vks = json.loads(files["bifrost/config.json"])["governance"]["rate_limits"]
    rl = next(r for r in vks if r["id"] == "rl-key-cloud-tool")
    assert (rl["request_max_limit"], rl["request_reset_duration"]) == (25, "10m")  # exact


def test_duration_refuses_a_fraction_of_a_second():
    assert gw._duration(90) == "90s"
    with pytest.raises(gw.GatewaySpecError):
        gw._duration(0.5)


# --- audit of rendered files (what --check runs on disk) -----------------------------------------


def lab_files():
    spec = gw.load_spec(LAB_SPEC)
    return spec, dict(gw.render(spec))


def test_audit_passes_the_rendered_lab_config():
    spec, files = lab_files()
    assert gw.audit(files, spec) == []


def test_audit_catches_a_hand_added_cloud_fallback_in_litellm():
    spec, files = lab_files()
    doc = yaml.safe_load(files["litellm/config.yaml"])
    doc["model_list"].append(
        {"model_name": "cloud-x", "litellm_params": {"model": "anthropic/example-cloud-1"}}
    )
    doc["router_settings"]["fallbacks"] = [{"fast-classifier": ["cloud-x"]}]
    files["litellm/config.yaml"] = yaml.safe_dump(doc)
    problems = gw.audit(files, spec)
    assert problems == [
        "litellm/config.yaml: fallbacks: fast-classifier "
        "(profile:reader is data_tier local-only) falls back to non-local cloud-x"
    ]


def test_audit_catches_a_cloud_deployment_and_a_default_fallback_in_litellm():
    spec, files = lab_files()
    doc = yaml.safe_load(files["litellm/config.yaml"])
    doc["model_list"][0]["litellm_params"]["api_base"] = "https://api.example.com/v1"
    doc["router_settings"]["default_fallbacks"] = ["elsewhere"]
    files["litellm/config.yaml"] = yaml.safe_dump(doc)
    problems = "\n".join(gw.audit(files, spec))
    assert (
        "fast-classifier (profile:reader is data_tier local-only) has a cloud deployment"
        in problems
    )
    assert "default_fallbacks names non-local elsewhere" in problems


def test_audit_catches_cloud_routes_and_keys_in_bifrost():
    spec, files = lab_files()
    doc = json.loads(files["bifrost/config.json"])
    doc["providers"]["anthropic"] = {"keys": [{"models": ["main-reasoner"], "value": "env.X"}]}
    doc["governance"]["routing_rules"][0]["fallbacks"].append("anthropic/main-reasoner")
    vk = next(v for v in doc["governance"]["virtual_keys"] if v["name"] == "agent-reader")
    vk["provider_configs"].append({"provider": "anthropic", "allowed_models": ["*"]})
    files["bifrost/config.json"] = json.dumps(doc)
    problems = "\n".join(gw.audit(files, spec))
    assert (
        "main-reasoner (profile:responder is data_tier local-only) is served by non-local anthropic"
        in problems
    )
    assert "routing rule route-main-reasoner sends main-reasoner to non-local anthropic" in problems
    assert "local-only key agent-reader may call non-local anthropic" in problems


def test_bifrost_admin_api_needs_a_login_and_the_file_is_authoritative():
    spec, files = lab_files()
    doc = json.loads(files["bifrost/config.json"])
    assert doc["source_of_truth"] == "config.json"
    assert doc["governance"]["auth_config"] == {
        "admin_username": "admin",
        "admin_password": "env.HNX_SECRET_LLM_GATEWAY_BIFROST_ADMIN_PASSWORD",
        "is_enabled": True,
    }
    del doc["governance"]["auth_config"]
    doc["source_of_truth"] = "split"
    files["bifrost/config.json"] = json.dumps(doc)
    problems = "\n".join(gw.audit(files, spec))
    assert "the admin API has no login" in problems
    assert 'source_of_truth is not "config.json"' in problems


def test_bifrost_admin_password_is_a_secret_of_its_own(tmp_path):
    with pytest.raises(gw.GatewaySpecError, match="must be a secret:"):
        gw.render_file(make_spec(tmp_path, bifrost={"admin_password": "fake-literal"}))
    shared = {"admin_password": "secret:llm-gateway/master-key"}
    with pytest.raises(gw.GatewaySpecError, match=r"master_key and bifrost\.admin_password use"):
        gw.render_file(make_spec(tmp_path, bifrost=shared))


def test_check_fails_on_a_tampered_output_dir_and_on_drift(tmp_path, capsys):
    out = tmp_path / "out"
    shutil.copytree(LAB, out)
    assert hnx(["gen", "gateway", "render", str(LAB_SPEC), str(out), "--check"]) == 0
    cfg = out / "litellm" / "config.yaml"
    doc = yaml.safe_load(cfg.read_text())
    doc["router_settings"]["context_window_fallbacks"] = [{"fast-classifier": ["x"]}]
    cfg.write_text(yaml.safe_dump(doc))
    assert hnx(["gen", "gateway", "render", str(LAB_SPEC), str(out), "--check"]) == 1
    err = capsys.readouterr().err
    assert "differs: litellm/config.yaml" in err
    assert "context_window_fallbacks: fast-classifier" in err


def test_render_writes_and_is_idempotent(tmp_path, capsys):
    spec = make_spec(tmp_path)
    out = tmp_path / "out"
    assert hnx(["gen", "gateway", "render", str(spec), str(out)]) == 0
    assert hnx(["gen", "gateway", "render", str(spec), str(out)]) == 0
    assert "wrote 0, unchanged 5" in capsys.readouterr().out


def test_bad_spec_exits_1(tmp_path, capsys):
    spec = make_spec(tmp_path, master_key="literal")
    assert hnx(["gen", "gateway", "render", str(spec), str(tmp_path / "o")]) == 1
    assert "must be a secret" in capsys.readouterr().err


# --- provisioning LiteLLM keys (a stdlib fake of LiteLLM's key API) -----------------------------


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


class FakeKeyAPI:
    """LiteLLM's key store as it behaves: keys are kept by token (sha256 of an sk- value), aliases
    are unique, ``/key/update``'s ``key`` names the key to change (a value or its token), a
    deleted key stops authenticating, and ``/key/list`` pages (``page``, ``size``,
    ``total_pages``) and returns full objects, ``metadata`` included, on ``return_full_object``."""

    def __init__(self):
        self.keys: dict[str, dict] = {}  # token -> stored body (without the value)
        self.users: dict[str, dict] = {}  # user_id -> stored body
        self.calls: list[tuple[str, str]] = []
        api = self

        def token(k):
            return sha(k) if k.startswith("sk-") else k

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, status, out):
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urlsplit(self.path)
                api.calls.append((url.path, self.headers.get("Authorization", "")))
                q = parse_qs(url.query)
                if url.path == "/user/info":
                    uid = q.get("user_id", [""])[0]
                    if uid not in api.users:
                        return self.reply(404, {"detail": f"User {uid} not found"})
                    return self.reply(200, {"user_id": uid, "user_info": api.users[uid]})
                alias = q.get("key_alias", [None])[0]
                full = q.get("return_full_object", ["false"])[0] == "true"
                page, size = int(q.get("page", ["1"])[0]), int(q.get("size", ["10"])[0])
                rows = [
                    {"token": t, "key_alias": b["key_alias"]}
                    | ({"metadata": b.get("metadata") or {}} if full else {})
                    for t, b in api.keys.items()
                    if alias is None or b["key_alias"] == alias
                ]
                pages = max(1, -(-len(rows) // size))
                shown = rows[(page - 1) * size : page * size]
                self.reply(
                    200,
                    {
                        "keys": shown,
                        "total_count": len(rows),
                        "current_page": page,
                        "total_pages": pages,
                    },
                )

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                api.calls.append((self.path, self.headers.get("Authorization", "")))
                if self.path == "/key/generate":
                    t = token(body["key"])
                    if t in api.keys or any(
                        b["key_alias"] == body["key_alias"] for b in api.keys.values()
                    ):
                        return self.reply(400, {"error": {"message": "Key already exists"}})
                    api.keys[t] = {k: v for k, v in body.items() if k != "key"}
                    return self.reply(200, {"key": "sk-...", "key_alias": body["key_alias"]})
                if self.path == "/key/update":
                    t = token(body["key"])
                    if t not in api.keys:
                        return self.reply(404, {"error": {"message": "Key not found"}})
                    api.keys[t] |= {k: v for k, v in body.items() if k != "key"}
                    return self.reply(200, {"key_alias": api.keys[t]["key_alias"]})
                if self.path == "/user/new":
                    if body["user_id"] in api.users:
                        return self.reply(400, {"error": {"message": "user exists"}})
                    api.users[body["user_id"]] = dict(body)
                    return self.reply(200, {"user_id": body["user_id"]})
                if self.path == "/user/update":
                    if body["user_id"] not in api.users:
                        return self.reply(404, {"error": {"message": "user not found"}})
                    api.users[body["user_id"]] |= body
                    return self.reply(200, {"user_id": body["user_id"]})
                if self.path == "/key/delete":
                    gone = [token(k) for k in body["keys"] if api.keys.pop(token(k), None)]
                    return self.reply(200, {"deleted_keys": gone})
                self.reply(404, {"error": {"message": "no route"}})

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        self.url = f"http://{LOOPBACK}:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def valid(self, value):
        return sha(value) in self.keys


def lab_keys():
    doc = json.loads((LAB / "litellm" / "keys.json").read_text())
    return doc, {k["key_env"]: f"sk-fake-{k['key_alias']}" for k in doc["keys"]}


def test_provision_creates_then_updates_keys_from_the_environment():
    api = FakeKeyAPI()
    try:
        doc, env = lab_keys()
        lines = gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)
        assert len(lines) == 3 and all(": created (" in ln for ln in lines)
        lines = gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)  # idempotent
        assert all(": updated (" in ln for ln in lines)
        assert [p for p, _ in api.calls].count("/key/update") == 3
        assert {a for _, a in api.calls} == {"Bearer sk-fake-master"}
        assert api.keys[sha("sk-fake-conformance-throttle")]["rpm_limit"] == 3
        assert "key_env" not in api.keys[sha("sk-fake-agent-reader")]
        assert len(api.keys) == 3
    finally:
        api.httpd.shutdown()


def test_provision_rotates_a_changed_key_and_the_old_value_stops_working():
    api = FakeKeyAPI()
    try:
        doc, env = lab_keys()
        gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)
        reader_env = next(k["key_env"] for k in doc["keys"] if k["key_alias"] == "agent-reader")
        old, new = env[reader_env], "sk-fake-agent-reader-rotated"
        lines = gw.provision_litellm(
            doc, api.url, "sk-fake-master", environ=env | {reader_env: new}
        )
        assert "key agent-reader: rotated (fast-classifier)" in lines
        assert api.valid(new) and not api.valid(old)
        stored = api.keys[sha(new)]
        assert stored["key_alias"] == "agent-reader" and stored["models"] == ["fast-classifier"]
        assert len(api.keys) == 3  # nothing left behind under the alias
    finally:
        api.httpd.shutdown()


def test_provision_refuses_a_missing_key_and_plaintext_off_loopback():
    doc = {"keys": [{"key_alias": "a", "key_env": "HNX_SECRET_A", "models": ["m"]}]}
    with pytest.raises(gw.GatewaySpecError, match="HNX_SECRET_A is not set"):
        gw.provision_litellm(doc, f"http://{LOOPBACK}:9", "m", environ={})
    url = "http://gateway.example.internal:4000"  # no-raw-endpoint: allow refused, never called
    with pytest.raises(ValueError, match="plaintext"):
        gw.provision_litellm(doc, url, "m", environ={})


def test_provision_deletes_the_keys_of_profiles_removed_from_the_spec(monkeypatch):
    """A profile dropped from the spec loses its key: every key tagged with this gateway's name
    that the file no longer declares is deleted (over every /key/list page); a key nobody tagged
    is left alone and listed."""
    monkeypatch.setattr(gw, "_PAGE", 1)  # one key a page: the prune must follow total_pages
    api = FakeKeyAPI()
    try:
        doc, env = lab_keys()
        assert doc["managed_by"] == "lab-in-a-box"
        assert all(k["metadata"][gw.MANAGED] == "lab-in-a-box" for k in doc["keys"])
        gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)
        api.keys[sha("sk-fake-by-hand")] = {"key_alias": "by-hand", "metadata": {}}
        reader_env = next(k["key_env"] for k in doc["keys"] if k["key_alias"] == "agent-reader")
        fewer = doc | {"keys": [k for k in doc["keys"] if k["key_alias"] != "agent-reader"]}
        kept = gw.provision_litellm(fewer, api.url, "sk-fake-master", environ=env, prune=False)
        assert api.valid(env[reader_env]) and not any("deleted" in ln for ln in kept)
        dry = gw.provision_litellm(fewer, api.url, "sk-fake-master", environ=env, dry_run=True)
        assert "key agent-reader: would be deleted (no longer declared by lab-in-a-box)" in dry
        assert api.valid(env[reader_env]), "a dry run deleted a key"
        assert not [c for c, _ in api.calls[-6:] if c != "/key/list"], "a dry run wrote"
        seen = []
        lines = gw.provision_litellm(
            fewer, api.url, "sk-fake-master", environ=env, emit=seen.append
        )
        assert seen == lines
        assert "key agent-reader: deleted (no longer declared by lab-in-a-box)" in lines
        assert any("untagged key(s)" in ln and "by-hand" in ln for ln in lines)
        assert not api.valid(env[reader_env]), "a removed profile's key still works"
        assert api.valid("sk-fake-by-hand"), "an untagged key was deleted"
        assert len(api.keys) == 3
        again = gw.provision_litellm(fewer, api.url, "sk-fake-master", environ=env)
        assert not any(": deleted" in ln for ln in again)  # idempotent
    finally:
        api.httpd.shutdown()


def test_one_gateway_never_prunes_another_gateways_keys_and_an_empty_file_prunes_nothing():
    """Two gateway specs on one proxy: each prunes only keys tagged with its own name.  A keys
    file that declares nothing, or has no managed_by, deletes nothing; one that does not parse is
    refused."""
    api = FakeKeyAPI()
    try:
        lab, lab_env = lab_keys()
        ex = json.loads((ROOT / "examples/model-serving/gateway/litellm/keys.json").read_text())
        ex_env = {k["key_env"]: f"sk-fake-ex-{k['key_alias']}" for k in ex["keys"]}
        gw.provision_litellm(lab, api.url, "sk-m", environ=lab_env)
        lines = gw.provision_litellm(ex, api.url, "sk-m", environ=ex_env)
        assert not any("deleted" in ln for ln in lines), lines
        assert all(api.valid(lab_env[k["key_env"]]) for k in lab["keys"])
        empty = gw.provision_litellm(lab | {"keys": []}, api.url, "sk-m", environ={})
        assert any("prune refused" in ln for ln in empty)
        unnamed = {"keys": lab["keys"][:1]}
        assert any(
            "prune skipped" in ln
            for ln in gw.provision_litellm(unnamed, api.url, "sk-m", environ=lab_env)
        )
        assert len(api.keys) == 4  # nothing of either gateway was deleted
        for bad in ({"keys": "x"}, [], {"nokeys": 1}, {"keys": [{"key_env": "E"}]}):
            with pytest.raises(gw.GatewaySpecError, match="not an object with a list of keys"):
                gw.provision_litellm(bad, api.url, "sk-m", environ={})
    finally:
        api.httpd.shutdown()


def test_check_fails_a_key_without_the_managed_tag_or_with_a_duplicate_alias(tmp_path, capsys):
    out = tmp_path / "out"
    shutil.copytree(LAB, out)
    keys = out / "litellm" / "keys.json"
    on_disk = json.loads(keys.read_text())
    for k in on_disk["keys"]:
        k["metadata"].pop(gw.MANAGED)
    keys.write_text(json.dumps(on_disk, indent=2) + "\n")
    assert hnx(["gen", "gateway", "render", str(LAB_SPEC), str(out), "--check"]) == 1
    assert "keys.json: key agent-reader is not tagged metadata.hnx-managed='lab-in-a-box'" in (
        capsys.readouterr().err
    )
    doc, _ = lab_keys()
    assert gw._audit_keys(json.dumps(doc), "lab-in-a-box") == []
    untagged = json.loads(json.dumps(doc))
    del untagged["keys"][0]["metadata"][gw.MANAGED]
    (p,) = gw._audit_keys(json.dumps(untagged), "lab-in-a-box")
    assert "not tagged metadata.hnx-managed" in p
    other = json.loads(json.dumps(doc))
    other["keys"][0]["metadata"][gw.MANAGED] = True
    assert len(gw._audit_keys(json.dumps(other), "lab-in-a-box")) == 1
    twice = doc | {"keys": [doc["keys"][0], doc["keys"][0]]}
    assert gw._audit_keys(json.dumps(twice), "lab-in-a-box") == [
        f"key {doc['keys'][0]['key_alias']} is declared twice"
    ]
    assert gw._audit_keys(json.dumps(doc), "elsewhere")[0].startswith("managed_by is")
    assert gw._audit_keys("[]") == ["not a JSON object with a keys list"]


def test_a_spec_name_must_be_a_slug(tmp_path):
    spec = LAB_SPEC.read_text().replace("name: lab-in-a-box", "name: Lab In A Box")
    (tmp_path / "gateway.yml").write_text(spec)
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.spec_from_dict(yaml.safe_load(spec), base=LAB)
    assert any("must be a lower-case slug" in p for p in exc.value.problems)


# --- the telemetry reader (docs/orchestration-telemetry.md) ------------------------------------
ORCH = ROOT / "examples" / "llm-orchestrator-gateway"


def reader_keys():
    _, keys_json = gw.render_litellm(gw.load_spec(ORCH / "gateway.yml"))
    return json.loads(keys_json)


def test_the_reader_is_a_view_only_user_with_one_spend_log_key():
    spec = gw.load_spec(ORCH / "gateway.yml")
    doc = reader_keys()
    assert doc["users"] == [
        {
            "user_id": "hnx-telemetry-reader-llm-orchestrator-example",
            "user_role": "proxy_admin_viewer",
            "models": ["no-default-models"],
        }
    ]
    (key,) = [k for k in doc["keys"] if k["key_alias"] == "telemetry-reader"]
    assert key["key_env"] == "HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER"
    assert key["allowed_routes"] == ["/spend/logs/v2"] and key["models"] == ["no-default-models"]
    assert key["user_id"] == doc["users"][0]["user_id"]
    assert key["metadata"][gw.MANAGED] == "llm-orchestrator-example"  # pruned like any key
    assert gw._audit_keys(json.dumps(doc), spec.name) == []
    # every other key stays a plain model key
    assert all("allowed_routes" not in k for k in doc["keys"] if k is not key)


@pytest.mark.parametrize(
    ("edit", "words"),
    [
        (
            lambda d: d["keys"][-1].update(allowed_routes=["/spend/logs/v2", "/key/generate"]),
            "only the",
        ),
        (lambda d: d["keys"][-1].update(models=[]), "only the telemetry reader"),
        (lambda d: d["keys"][0].update(allowed_routes=["/spend/logs/v2"]), "only the"),
        (lambda d: d["users"][0].update(user_role="proxy_admin"), "users: each user"),
        (lambda d: d["users"][0].update(models=[]), "users: each user"),
        (lambda d: d["users"].append({"user_id": "x", "user_role": "proxy_admin_viewer"}), "users"),
        (lambda d: d["keys"][-1].update(user_id="someone-else"), "a user of users"),
        (lambda d: d["keys"][-1].pop("user_id"), "a user of users"),
        (lambda d: d["keys"][-1].update(key_type="llm_api"), "key_type widens"),
        (lambda d: d["keys"][-1].update(team_id="t"), "team_id widens"),
        (lambda d: d["keys"][-1].update(rpm_limit=1), "only the telemetry reader"),
        (lambda d: d["keys"][0].update(key_type="management"), "key_type widens"),
        (lambda d: d["keys"][0].update(permissions={"get_spend_routes": True}), "permissions"),
        (lambda d: d["keys"][0].update(models=["all-proxy-models"]), "names every model"),
        (lambda d: d["keys"][0].update(key_alias="telemetry-reader"), "only the telemetry"),
        (lambda d: d.update(users={}), "users: each user"),
    ],
)
def test_the_audit_refuses_a_reader_that_could_do_more(edit, words):
    doc = reader_keys()
    assert doc["keys"][-1]["key_alias"] == "telemetry-reader"
    edit(doc)
    problems = gw._audit_keys(json.dumps(doc), "llm-orchestrator-example")
    assert any(words in p for p in problems), problems


@pytest.mark.parametrize(
    ("block", "words"),
    [
        ({"key": "plain"}, "telemetry_reader.key"),
        ({"key": "secret:llm-gateway/key-telemetry-reader", "x": 1}, "telemetry_reader takes key"),
        ("secret:llm-gateway/key-telemetry-reader", "telemetry_reader takes key"),
        ({"key": "secret:llm-gateway/key-home-vllm-a"}, "use the same secret"),
        ({"key": "secret:llm-gateway/master-key"}, "use the same secret"),
    ],
)
def test_a_bad_reader_block_is_a_spec_error(tmp_path, block, words):
    d = tmp_path / "s"
    shutil.copytree(ORCH, d, ignore=shutil.ignore_patterns("gateway"))
    doc = yaml.safe_load((d / "gateway.yml").read_text(encoding="utf-8"))
    doc["telemetry_reader"] = block
    (d / "gateway.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.load_spec(d / "gateway.yml")
    assert any(words in p for p in exc.value.problems), exc.value.problems


def test_a_key_named_like_the_reader_is_refused(tmp_path):
    d = tmp_path / "s"
    shutil.copytree(ORCH, d, ignore=shutil.ignore_patterns("gateway"))
    doc = yaml.safe_load((d / "gateway.yml").read_text(encoding="utf-8"))
    doc["keys"][0]["name"] = "telemetry-reader"
    (d / "gateway.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.load_spec(d / "gateway.yml")
    assert any("is the telemetry reader's" in p for p in exc.value.problems)


def test_provision_creates_the_reader_user_without_a_spare_key_then_updates_it():
    api = FakeKeyAPI()
    try:
        doc = reader_keys()
        env = {k["key_env"]: f"sk-fake-{k['key_alias']}" for k in doc["keys"]}
        uid = doc["users"][0]["user_id"]
        dry = gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env, dry_run=True)
        assert f"user {uid}: would be created (proxy_admin_viewer)" in dry
        assert not api.users and not api.keys, "a dry run wrote"
        lines = gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)
        assert lines[0] == f"user {uid}: created (proxy_admin_viewer)"  # before its key
        assert api.users[uid] == {
            "user_id": uid,
            "user_role": "proxy_admin_viewer",
            "models": ["no-default-models"],
            "auto_create_key": False,  # /user/new would otherwise mint an undeclared key
        }
        assert "key telemetry-reader: created (routes /spend/logs/v2)" in lines
        stored = api.keys[sha("sk-fake-telemetry-reader")]
        assert stored["allowed_routes"] == ["/spend/logs/v2"] and stored["user_id"] == uid
        api.users[uid]["user_role"] = "proxy_admin"  # widened by hand: provisioning puts it back
        again = gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)
        assert f"user {uid}: updated (proxy_admin_viewer)" in again
        assert api.users[uid]["user_role"] == "proxy_admin_viewer"
        # the reader dropped from the spec: its key is pruned like any other
        fewer = doc | {"users": [], "keys": [k for k in doc["keys"] if "user_id" not in k]}
        gone = gw.provision_litellm(fewer, api.url, "sk-fake-master", environ=env)
        assert any("key telemetry-reader: deleted" in ln for ln in gone)
        assert not api.valid("sk-fake-telemetry-reader")
    finally:
        api.httpd.shutdown()


@pytest.mark.parametrize(
    "doc",
    [
        {"users": [{"user_role": "proxy_admin_viewer"}], "keys": []},
        {"users": [{"user_id": "u", "user_role": "proxy_admin", "models": []}], "keys": []},
        {"keys": [{"key_alias": "a", "key_env": "X", "models": ["m"], "key_type": "management"}]},
    ],
)
def test_provision_refuses_a_keys_file_that_grants_more_before_any_request(doc):
    """A hand-edited or stale keys file never reaches the proxy: an admin user, a user of
    another shape or a widened key is refused before the first request (port 9 is never
    called)."""
    with pytest.raises(gw.GatewaySpecError, match="grants more than a gateway spec declares"):
        gw.provision_litellm(doc, f"http://{LOOPBACK}:9", "m", environ={"X": "sk-x"})


# --- TLP ceilings (ADR-0033 decisions 10, 11, 12) -------------------------------------------------
TERMS = {"retention": "none", "training": "none", "ref": "the provider's terms, 2026-09"}
#: the rendered keys file and proxy config (named by the files the generator writes)
_RENDERED = sorted(gw.render(gw.load_spec(LAB_SPEC)))
KEYS = next(f for f in _RENDERED if f.endswith("/keys.json"))
CONFIG = next(f for f in _RENDERED if f.endswith("/config.yaml"))


def _params(deployment: dict) -> dict:
    return next(v for k, v in deployment.items() if k.endswith("_params"))


def test_every_key_carries_its_sending_tlp_ceiling(tmp_path):
    spec = gw.load_spec(make_spec(tmp_path))
    assert {k.name: k.tlp_ceiling for k in spec.keys} == {
        "local-agent": gw.tlp.Label.RED,  # local-only: red, the reading that sends nothing out
        "cloud-tool": gw.tlp.Label.CLEAR,  # cloud-allowed: clear, the only ceiling it allows
    }
    assert spec.ceilings == {
        "agent-local": gw.tlp.Label.RED,
        "small-local": gw.tlp.Label.RED,
        # the spec puts it on a cloud backend: clear, though the table marks no leaves_lab
        "cloud-reasoner": gw.tlp.Label.CLEAR,
    }
    keys = {k["key_alias"]: k for k in json.loads(gw.render(spec)[KEYS])["keys"]}
    assert keys["local-agent"]["metadata"]["tlp_ceiling"] == "red"
    assert keys["cloud-tool"]["metadata"]["tlp_ceiling"] == "clear"


def _roles_with(**cloud):
    roles = copy.deepcopy(ROLES)
    roles["roles"]["cloud-reasoner"].update(cloud)
    return roles


def test_a_raised_role_keeps_its_ceiling_at_the_gateway(tmp_path):
    roles = _roles_with(tlp_ceiling="green")
    roles["roles"]["cloud-reasoner"]["bindings"][0].update(leaves_lab=True, provider_terms=TERMS)
    spec = gw.load_spec(make_spec(tmp_path, roles))
    assert spec.ceilings["cloud-reasoner"] is gw.tlp.Label.GREEN


def test_a_role_table_ceiling_the_rules_refuse_is_refused(tmp_path):
    roles = _roles_with(tlp_ceiling="amber")
    roles["roles"]["cloud-reasoner"]["bindings"][0]["leaves_lab"] = True
    with pytest.raises(gw.GatewaySpecError, match="amber and above are never granted"):
        gw.load_spec(make_spec(tmp_path, roles))


def test_a_key_above_a_cloud_roles_ceiling_is_not_scoped_to_it(tmp_path):
    """The table marks the role leaves_lab while the spec calls its backend local: the locality
    rule passes (it reads the spec), and the TLP rule (which reads the table too) refuses the
    local-only key scoped to it."""
    roles = copy.deepcopy(ROLES)
    roles["roles"]["small-local"]["bindings"][0]["leaves_lab"] = True
    with pytest.raises(gw.GatewaySpecError) as ei:
        gw.load_spec(make_spec(tmp_path, roles))
    msg = str(ei.value)
    assert (
        "key local-agent sends at TLP ceiling red but may call mdl:small-local (down a fallback "
        "chain), whose prompts can leave the lab at ceiling clear"
    ) in msg, msg


@pytest.mark.parametrize(
    "ceiling, tier, words",
    [
        ("green", "cloud-allowed", "data_tier cloud-allowed disagrees with tlp_ceiling green"),
        ("clear", "local-only", "data_tier local-only disagrees with tlp_ceiling clear"),
        ("amber-strict", "local-only", "not a TLP label"),
        ("tlp:red", "local-only", "is not written as 'red'"),
    ],
)
def test_a_declared_key_ceiling_must_be_a_label_that_agrees_with_its_data_tier(
    tmp_path, ceiling, tier, words
):
    keys = spec_doc()["keys"]
    keys[1].update(tlp_ceiling=ceiling, data_tier=tier)
    with pytest.raises(gw.GatewaySpecError, match=re.escape(words)):
        gw.load_spec(make_spec(tmp_path, keys=keys))


def test_a_profiles_tlp_ceiling_is_its_keys(tmp_path):
    prof = {
        "id": "profile:researcher",
        "model_role": "mdl:cloud-reasoner",
        "data_tier": "cloud-allowed",
        "tlp_ceiling": "clear",
    }
    (tmp_path / "profile.researcher.json").write_text(json.dumps(prof))
    spec = gw.load_spec(make_spec(tmp_path, profiles=["profile.*.json"]))
    (key,) = [k for k in spec.keys if k.owner == "profile:researcher"]
    assert key.tlp_ceiling is gw.tlp.Label.CLEAR
    prof["tlp_ceiling"] = "green"  # a cloud-allowed profile above clear disagrees
    (tmp_path / "profile.researcher.json").write_text(json.dumps(prof))
    with pytest.raises(gw.GatewaySpecError, match="disagrees with tlp_ceiling green"):
        gw.load_spec(make_spec(tmp_path, profiles=["profile.*.json"]))


@pytest.mark.parametrize(
    "edit", [lambda m: m.pop("tlp_ceiling"), lambda m: m.update(tlp_ceiling="x")]
)
def test_audit_reads_a_missing_or_edited_key_ceiling_as_red(tmp_path, edit):
    spec = gw.load_spec(make_spec(tmp_path))
    files = dict(gw.render(spec))
    assert gw.audit(files, spec) == []
    doc = json.loads(files[KEYS])
    (cloud,) = [k for k in doc["keys"] if k["key_alias"] == "cloud-tool"]
    edit(cloud["metadata"])
    files[KEYS] = json.dumps(doc)
    assert gw.audit(files, spec) == [
        f"{KEYS}: key cloud-tool (metadata.tlp_ceiling read as red) lists "
        "cloud-reasoner, which has a cloud deployment at TLP ceiling clear"
    ]


def test_audit_holds_a_hand_scoped_key_to_the_cloud_ceiling(tmp_path):
    """A local-only key edited to list a cloud model is caught by the ceiling, read from the
    rendered config (the spec reads the role as cloud) and from a role the spec reads as local."""
    spec = gw.load_spec(make_spec(tmp_path))
    files = dict(gw.render(spec))
    doc = json.loads(files[KEYS])
    (local,) = [k for k in doc["keys"] if k["key_alias"] == "local-agent"]
    local["models"].append("cloud-reasoner")
    files[KEYS] = json.dumps(doc)
    cfg = yaml.safe_load(files[CONFIG])
    for d in cfg["model_list"]:
        if d["model_name"] == "small-local":
            _params(d)["api_base"] = "https://api.example.com/v1"
    files[CONFIG] = yaml.safe_dump(cfg)
    problems = [p for p in gw.audit(files, spec) if "TLP ceiling" in p]
    assert problems == [
        f"{KEYS}: key local-agent (metadata.tlp_ceiling read as red) lists "
        "small-local, which has a cloud deployment at TLP ceiling clear",
        f"{KEYS}: key local-agent (metadata.tlp_ceiling read as red) lists "
        "cloud-reasoner, which has a cloud deployment at TLP ceiling clear",
    ]
