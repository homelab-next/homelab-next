# SPDX-License-Identifier: Apache-2.0
"""The serving plan (homelabnext.models.serving): store + role table + serving spec -> what each
engine serves, the vllm_server instances, the drift check; and the gateway generator's
``serving:`` key, which declares the store-served backends from the same plan."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.cli import main as hnx
from homelabnext.generators import llm_gateway as gw
from homelabnext.models import serving as sv

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "model-serving"


def spec() -> dict:
    return yaml.safe_load((EXAMPLE / "serving.yml").read_text())


def workdir(tmp_path: Path, serving: dict | None = None, roles: dict | None = None) -> Path:
    """A copy of the example in ``tmp_path`` with an edited serving spec or role table."""
    for name in ("model_store.json", "model_roles.json", "serving.yml", "gateway.yml"):
        shutil.copy(EXAMPLE / name, tmp_path / name)
    if serving is not None:
        (tmp_path / "serving.yml").write_text(yaml.safe_dump(serving))
    if roles is not None:
        (tmp_path / "model_roles.json").write_text(json.dumps(roles))
    return tmp_path / "serving.yml"


def roles() -> dict:
    return json.loads((EXAMPLE / "model_roles.json").read_text())


def problems_of(tmp_path, serving=None, roles=None) -> list[str]:
    with pytest.raises(sv.ServingSpecError) as exc:
        sv.load_plan(workdir(tmp_path, serving, roles))
    return exc.value.problems


def test_the_example_plan_binds_each_backend_to_one_store_entry():
    plan = sv.load_plan(EXAMPLE / "serving.yml")
    got = {n: (b.engine, b.entry.id, b.model_id, b.max_model_len) for n, b in plan.backends.items()}
    assert got == {
        "inference-large": ("vllm", "example-27b-fp8", "example-27b", 131072),
        "inference-triage": ("vllm", "example-4b-triage", "example-4b-triage", 32768),
        "inference-small": ("llama-server", "example-4b-q4km", "example-4b", 8192),
    }
    inst = plan.instance(plan.backends["inference-large"])
    assert inst["model_path"].endswith("snapshots/174d4518adc353b21f63bbd7186645da35935aeb")
    assert inst["digest"] == plan.store.entries["example-27b-fp8"].digest
    assert inst["args"] == ["--enable-auto-tool-choice", "--max-num-seqs", "24",
                            "--tool-call-parser", "qwen3_xml"]  # fmt: skip


def test_render_is_deterministic_and_the_check_catches_drift(tmp_path, capsys):
    a = sv.render(sv.load_plan(EXAMPLE / "serving.yml"))
    assert a == sv.render(sv.load_plan(EXAMPLE / "serving.yml"))
    assert list(a) == ["vllm_server/instances.yml"]
    assert "inference-small" not in a["vllm_server/instances.yml"]  # llama-server: not vllm's
    assert hnx(["models", "serving", "check", str(EXAMPLE / "serving.yml"), str(EXAMPLE)]) == 0
    out = tmp_path / "out"
    assert hnx(["models", "serving", "render", str(EXAMPLE / "serving.yml"), str(out)]) == 0
    p = out / "vllm_server" / "instances.yml"
    p.write_text(p.read_text().replace("max_model_len: 131072", "max_model_len: 65536"))
    assert hnx(["models", "serving", "check", str(EXAMPLE / "serving.yml"), str(out)]) == 1
    assert "differs: vllm_server/instances.yml" in capsys.readouterr().err


def test_a_binding_the_backends_engine_cannot_serve_is_refused(tmp_path):
    s = spec()
    s["backends"]["svc:inference-small"]["engine"] = "vllm"  # the GGUF classifier on vLLM
    s["backends"]["svc:inference-small"]["gpus"] = [3]
    found = problems_of(tmp_path, s)
    assert any("no store entry for 'example-4b' may be served by vllm" in p for p in found)
    ok = tmp_path / "ok"
    ok.mkdir()
    assert sv.load_plan(workdir(ok)).backends["inference-small"].engine == "llama-server"


def test_a_binding_with_no_store_entry_is_refused(tmp_path):
    r = roles()
    r["roles"]["triage"]["bindings"][0]["model_id"] = "example-4b-other"
    r["roles"]["triage"]["bindings"][0].pop("digest")
    assert any("no store entry serves model id 'example-4b-other'" in p
               for p in problems_of(tmp_path, roles=r))  # fmt: skip


def test_one_vllm_backend_serves_one_model(tmp_path):
    r = roles()
    r["roles"]["second"] = {
        "tier": "fast",
        "max_context_tokens": 32768,
        "bindings": [{"backend": "svc:inference-triage", "model_id": "example-4b-bf16"}],
    }
    assert any("one vLLM process serves one model" in p for p in problems_of(tmp_path, roles=r))


def test_the_roles_on_a_vllm_backend_must_agree_on_the_context_length(tmp_path):
    r = roles()
    r["roles"]["triage-long"] = {
        "tier": "fast",
        "max_context_tokens": 65536,
        "bindings": [{"backend": "svc:inference-triage", "model_id": "example-4b-triage"}],
    }
    (p,) = [p for p in problems_of(tmp_path, roles=r) if "max_context_tokens" in p]
    assert "[32768, 65536]" in p
    r = roles()
    del r["roles"]["triage"]["max_context_tokens"]
    assert any("found none" in p for p in problems_of(tmp_path, roles=r))


@pytest.mark.parametrize(
    ("edit", "needle"),
    [
        (lambda b: b["svc:inference-triage"].__setitem__("port", 8000), "port 8000 is also"),
        (lambda b: b["svc:inference-triage"].__setitem__("gpus", [1]), "GPU 1 is also"),
        (lambda b: b["svc:inference-large"].__setitem__("tensor_parallel_size", 4), "must equal"),
        (lambda b: b["svc:inference-large"].__setitem__("gpus", []), "must equal"),
        (lambda b: b["svc:inference-large"].__setitem__("port", 80), "1024-65535"),
        (lambda b: b["svc:inference-large"].__setitem__("gpu_memory_utilization", 1.5), "fraction"),
        (
            lambda b: b["svc:inference-large"]["args"].__setitem__("served-model-name", "x"),
            "set by the plan",
        ),
        (
            lambda b: b["svc:inference-large"]["args"].__setitem__("max-model-len", 4096),
            "set by the plan",
        ),
        (
            lambda b: b["svc:inference-large"]["args"].__setitem__("chat-template", "a b"),
            "not an allowed vLLM flag",
        ),
        (
            lambda b: b["svc:inference-large"]["args"].__setitem__("x", "a\nb"),
            "not an allowed vLLM flag",
        ),
        (lambda b: b["svc:inference-large"]["args"].__setitem__("Bad_Flag", 1), "not a flag name"),
        (lambda b: b["svc:inference-small"].__setitem__("engine", "unsloth-studio"), "GUI"),
        (lambda b: b["svc:inference-small"].__setitem__("engine", "ollama"), "engine must be"),
        (lambda b: b["svc:inference-small"].__setitem__("args", {"seed": 1}), "vLLM flags"),
        (
            lambda b: b.__setitem__(
                "svc:nobody-binds", {"engine": "vllm", "port": 9000, "gpus": [5]}
            ),
            "would serve nothing",
        ),
        (lambda b: b["svc:inference-large"].__setitem__("replicas", 2), "unknown key"),
    ],
)
def test_bad_backends_are_refused(tmp_path, edit, needle):
    s = spec()
    edit(s["backends"])
    found = problems_of(tmp_path, s)
    assert any(needle in p for p in found), found


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        # a value that is itself a flag: one mapping entry would render as two flags
        ({"enforce-eager": "--trust-remote-code"}, "true (a bare flag) or false"),
        ({"enforce-eager": "--host=0.0.0.0"}, "true (a bare flag) or false"),
        ({"tool-call-parser": "--trust-remote-code"}, "is not a short name"),
        ({"tool-call-parser": "-x"}, "is not a short name"),
        # argparse prefix matching and short options: exact allowlisted names only
        ({"trust-remote": True}, "--trust-remote is not an allowed vLLM flag"),
        ({"hos": "0.0.0.0"}, "--hos is not an allowed vLLM flag"),
        ({"tp": 1}, "--tp is not an allowed vLLM flag"),
        # flags the plan does not own but that load files, code or remote config
        ({"config": "/tmp/x.yaml"}, "--config is not an allowed vLLM flag"),
        ({"allowed-local-media-path": "/"}, "--allowed-local-media-path is not an allowed"),
        ({"middleware": "evil.mod"}, "--middleware is not an allowed"),
        ({"tokenizer": "org/remote"}, "--tokenizer is not an allowed"),
        ({"tool-parser-plugin": "/tmp/p.py"}, "--tool-parser-plugin is not an allowed"),
        ({"worker-extension-cls": "evil.Cls"}, "--worker-extension-cls is not an allowed"),
        ({"hf-overrides": "x"}, "--hf-overrides is not an allowed"),
        # typed values
        ({"seed": "1\n"}, "is not a whole number"),
        ({"max-num-seqs": 0}, "is not a whole number in [1, 65536]"),
        ({"max-num-seqs": 2.5}, "is not a whole number"),
        ({"max-num-seqs": True}, "is not a whole number"),
        ({"dtype": "float64"}, "is not one of auto"),
        ({"swap-space": -1}, "is not a number in [0, 1024]"),
        ({"enable-prefix-caching": "yes"}, "true (a bare flag) or false"),
    ],
)
def test_args_are_an_allowlist_with_typed_values(tmp_path, args, needle):
    s = spec()
    s["backends"]["svc:inference-large"]["args"] = args
    found = problems_of(tmp_path, s)
    assert any(needle in p for p in found), found


def test_allowed_args_render_typed_and_false_booleans_are_omitted(tmp_path):
    s = spec()
    s["backends"]["svc:inference-large"]["args"] = {
        "enforce-eager": False, "enable-prefix-caching": True, "block-size": 16,
        "swap-space": 4.5, "kv-cache-dtype": "fp8", "quantization": "compressed-tensors",
    }  # fmt: skip
    plan = sv.load_plan(workdir(tmp_path, s))
    assert plan.backends["inference-large"].args == (
        "--block-size", "16", "--enable-prefix-caching", "--kv-cache-dtype", "fp8",
        "--quantization", "compressed-tensors", "--swap-space", "4.5",
    )  # fmt: skip
    assert not set(sv.ALLOWED_ARGS) & sv.OWNED_FLAGS


def test_the_schema_and_the_role_share_the_plans_allowlist():
    schema = json.loads((ROOT / "schemas/platform/model_serving.schema.json").read_text())
    args = schema["properties"]["backends"]["additionalProperties"]["properties"]["args"]
    assert args["propertyNames"]["enum"] == sorted(sv.ALLOWED_ARGS)
    role_vars = ROOT / sv.ROLE_VARS
    assert role_vars.read_text() == sv.role_vars_text(), (
        f"regenerate {sv.ROLE_VARS} from homelabnext.models.serving.role_vars_text()"
    )


def test_a_plan_with_bad_inputs_says_which(tmp_path):
    s = copy.deepcopy(spec())
    s["store"] = "absent.json"
    with pytest.raises(sv.ServingSpecError, match="cannot read the store"):
        sv.load_plan(workdir(tmp_path, s))
    s = spec()
    (tmp_path / "bad").mkdir()
    workdir(tmp_path / "bad", s)
    (tmp_path / "bad" / "model_store.json").write_text('{"models": {}}')
    with pytest.raises(sv.ServingSpecError, match="model store invalid"):
        sv.load_plan(tmp_path / "bad" / "serving.yml")


# ---------------------------------------------------------------- the gateway reads the plan
def test_the_gateway_declares_its_local_backends_from_the_plan():
    spec_ = gw.load_spec(EXAMPLE / "gateway.yml")
    assert {n: (b.locality, b.host, b.port) for n, b in spec_.backends.items()} == {
        "inference-large": ("local", "inference-large.svc.example.internal", 8000),
        "inference-small": ("local", "inference-small.svc.example.internal", 8001),
        "inference-triage": ("local", "inference-triage.svc.example.internal", 8002),
    }
    files = gw.render(spec_)
    litellm = yaml.safe_load(files["litellm/config.yaml"])
    by_role = {m["model_name"]: m["litellm_params"] for m in litellm["model_list"]}
    assert by_role["main-reasoner"]["model"] == "openai/example-27b"  # --served-model-name
    assert (
        by_role["main-reasoner"]["api_base"]
        == "http://inference-large.svc.example.internal:8000/v1"  # no-raw-endpoint: allow the rendered example address
    )
    assert hnx(["gen", "gateway", "render", str(EXAMPLE / "gateway.yml"),
                str(EXAMPLE / "gateway"), "--check"]) == 0  # fmt: skip


def _gateway(tmp_path, **over) -> Path:
    workdir(tmp_path)
    g = yaml.safe_load((tmp_path / "gateway.yml").read_text())
    g.update(over)
    (tmp_path / "gateway.yml").write_text(yaml.safe_dump(g))
    return tmp_path / "gateway.yml"


def test_the_gateway_refuses_a_declared_backend_that_disagrees_with_the_plan(tmp_path):
    p = _gateway(tmp_path, backends={"svc:inference-large": {"locality": "local", "port": 9999}})
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.load_spec(p)
    assert any("runs it locally on port 8000 (vllm)" in x for x in exc.value.problems)
    (tmp_path / "ok").mkdir()
    declared = {"locality": "local", "port": 8000, "api_key": "secret:llm-gateway/backend-key"}
    ok = _gateway(tmp_path / "ok", backends={"svc:inference-large": declared})
    assert gw.load_spec(ok).backends["inference-large"].api_key == "secret:llm-gateway/backend-key"


def test_the_gateway_refuses_a_plan_that_does_not_resolve(tmp_path):
    r = roles()
    r["roles"]["main-reasoner"]["bindings"][0]["model_id"] = "example-70b"
    workdir(tmp_path, roles=r)
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.load_spec(tmp_path / "gateway.yml")
    assert any(p.startswith("serving: mdl:main-reasoner") for p in exc.value.problems)


def test_the_gateway_refuses_a_plan_on_another_role_table(tmp_path):
    p = _gateway(tmp_path)
    shutil.copy(tmp_path / "model_roles.json", tmp_path / "other_roles.json")
    s = spec()
    s["roles"] = "other_roles.json"
    (tmp_path / "serving.yml").write_text(yaml.safe_dump(s))
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.load_spec(p)
    assert any("another role table" in x for x in exc.value.problems)


def test_a_gateway_spec_without_serving_is_unchanged():
    """The lab's gateway (no serving: key) still renders exactly what is committed."""
    lab = ROOT / "compose" / "lab-in-a-box" / "config" / "llm-gateway"
    assert hnx(["gen", "gateway", "render", str(lab / "gateway.yml"), str(lab), "--check"]) == 0


def test_the_plan_states_its_exposure_and_the_gateway_refuses_a_loopback_one(tmp_path):
    s = spec()
    del s["exposure"]
    assert any("exposure must be one of" in p for p in problems_of(tmp_path, s))
    s["exposure"] = "loopback"
    plan = sv.load_plan(workdir(tmp_path, s))
    assert plan.exposure == "loopback"
    assert "vllm_server_exposure: loopback\n" in sv.render(plan)["vllm_server/instances.yml"]
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.render_file(tmp_path / "gateway.yml")
    assert any("has exposure loopback" in p for p in exc.value.problems), exc.value.problems


def test_a_registry_service_port_that_is_not_the_plans_is_refused(tmp_path):
    """A registry service silently won over the plan: the gateway called 9999, vLLM listened on
    8000.  Both say where the backend is, so they must agree."""
    workdir(tmp_path)
    reg = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())
    svc = dict(reg["services"]["inference"], capability="inference-large")
    reg["services"]["inference"]["port"] = 8100  # frees 8000 on that host for the plan's backend
    reg["services"]["inference-large"] = svc
    g = yaml.safe_load((tmp_path / "gateway.yml").read_text())
    g["registry"] = "registry.yml"
    g["domain"] = reg.get("lab", {}).get("domain", g["domain"])

    def render(port):
        svc["port"] = port
        (tmp_path / "registry.yml").write_text(yaml.safe_dump(reg))
        (tmp_path / "gateway.yml").write_text(yaml.safe_dump(g))
        return gw.render_file(tmp_path / "gateway.yml")

    with pytest.raises(gw.GatewaySpecError) as exc:
        render(9999)
    assert any("port 8000 (the spec or the serving plan) is not registry service" in p
               for p in exc.value.problems), exc.value.problems  # fmt: skip
    files = render(8000)
    lt = yaml.safe_load(files["litellm/config.yaml"])
    bases = {d["model_name"]: d["litellm_params"].get("api_base") for d in lt["model_list"]}
    assert bases["main-reasoner"].endswith(":8000/v1")
