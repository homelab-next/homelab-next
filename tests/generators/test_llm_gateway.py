# SPDX-License-Identifier: Apache-2.0
"""LLM gateway config generator: render, the locality rule, the audit of rendered files, the CLI
drift check and LiteLLM key provisioning (against a stdlib fake; no network)."""

from __future__ import annotations

import copy
import dataclasses
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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


def test_audit_refuses_a_self_declared_local_backend():
    spec, files = lab_files()
    bad = dataclasses.replace(spec.backends["inference-small"], host="api.example.com", port=443)
    spec.backends["inference-small"] = bad
    doc = yaml.safe_load(files["litellm/config.yaml"])
    for d in doc["model_list"]:
        if d["model_name"] == "fast-classifier":
            d["litellm_params"]["api_base"] = "https://api.example.com:443/v1"
    files["litellm/config.yaml"] = yaml.safe_dump(doc)
    problems = "\n".join(gw.audit(files, spec))
    assert "backend svc:inference-small is declared local but api.example.com" in problems
    assert (
        "fast-classifier (profile:reader is data_tier local-only) has a cloud deployment"
        in problems
    )


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


# --- provisioning LiteLLM keys (stdlib fake of /key/generate and /key/update) --------------------


class FakeKeyAPI:
    def __init__(self):
        self.keys: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                api.calls.append((self.path, self.headers.get("Authorization", "")))
                if self.path == "/key/generate" and body["key"] in api.keys:
                    status, out = 400, {"error": {"message": "Key already exists"}}
                else:
                    api.keys[body["key"]] = body
                    status, out = 200, {"key": "sk-...", "key_alias": body["key_alias"]}
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        self.url = f"http://{LOOPBACK}:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


def test_provision_creates_then_updates_keys_from_the_environment():
    api = FakeKeyAPI()
    try:
        doc = json.loads((LAB / "litellm" / "keys.json").read_text())
        env = {k["key_env"]: f"sk-fake-{k['key_alias']}" for k in doc["keys"]}
        lines = gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)
        assert len(lines) == 3 and all(": ok (" in ln for ln in lines)
        gw.provision_litellm(doc, api.url, "sk-fake-master", environ=env)  # idempotent
        assert [p for p, _ in api.calls].count("/key/update") == 3
        assert {a for _, a in api.calls} == {"Bearer sk-fake-master"}
        assert api.keys["sk-fake-conformance-throttle"]["rpm_limit"] == 3
        assert "key_env" not in api.keys["sk-fake-agent-reader"]
    finally:
        api.httpd.shutdown()


def test_provision_refuses_a_missing_key_and_plaintext_off_loopback():
    doc = {"keys": [{"key_alias": "a", "key_env": "HNX_SECRET_A", "models": ["m"]}]}
    with pytest.raises(gw.GatewaySpecError, match="HNX_SECRET_A is not set"):
        gw.provision_litellm(doc, f"http://{LOOPBACK}:9", "m", environ={})
    url = "http://gateway.example.internal:4000"  # no-raw-endpoint: allow refused, never called
    with pytest.raises(ValueError, match="plaintext"):
        gw.provision_litellm(doc, url, "m", environ={})
