# SPDX-License-Identifier: Apache-2.0
"""The controller's backend list and its agent homes, held to the gateway spec and the role table
(``hnx gen gateway render --check`` with a ``controller:`` block) and invariant A-14 (``hnx gen
gateway homes``: no home names an IP address or an engine model id)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.cli import main as hnx
from homelabnext.generators import agent_homes as ah
from homelabnext.generators import llm_gateway as gw
from homelabnext.registry.models import RoleTable

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "llm-orchestrator-gateway"
FIX = Path(__file__).resolve().parent / "fixtures"
FAIL = FIX / "controller-backends" / "fail"
HOMES = FIX / "hermes-homes"
ROLES = EXAMPLE / "model_roles.json"


# ---------------------------------------------------------------- the controller's backends
def test_the_example_controller_agrees_with_its_gateway_spec(capsys):
    spec = gw.load_spec(EXAMPLE / "gateway.yml")
    assert spec.controller is not None and set(spec.controller.homes) == {"vllm-a", "vllm-b"}
    assert ah.controller_problems(spec) == []
    out_dir = EXAMPLE / "gateway"
    assert (
        hnx(["gen", "gateway", "render", str(EXAMPLE / "gateway.yml"), str(out_dir), "--check"])
        == 0
    )
    assert "the controller's backends agree with it" in capsys.readouterr().out


def test_the_fail_fixture_breaks_each_rule_once():
    problems = ah.controller_problems(gw.load_spec(FAIL / "gateway.yml"))
    assert len(problems) == 4, problems
    by = {p.split(" (", 1)[0].removeprefix("controller backend "): p for p in problems}
    assert (
        "max_context 32768 differs from mdl:main-reasoner-a's max_context_tokens 131072"
        in (by["vllm-a"])
    )
    assert "mdl:main-reasoner-a is not bound to svc:vllm-b (bound to svc:vllm-a)" in by["vllm-b"]
    assert "svc:vllm-c is not a backend of the gateway spec" in by["vllm-c"]
    assert "model.default 'example-4b' is not a role" in by["vllm-d"]


def test_check_fails_on_the_controller_alone(tmp_path, capsys):
    """The rendered files are clean and current; only the controller disagrees: exit 1."""
    shutil.copytree(FAIL, tmp_path / "f")
    spec = tmp_path / "f" / "gateway.yml"
    assert hnx(["gen", "gateway", "render", str(spec), str(tmp_path / "out")]) == 0
    capsys.readouterr()
    assert hnx(["gen", "gateway", "render", str(spec), str(tmp_path / "out"), "--check"]) == 1
    err = capsys.readouterr().err
    assert err.count("gateway: controller backend ") == 4, err


def _with(tmp_path: Path, controller: dict, homes: dict[str, str] | None = None) -> gw.Spec:
    d = tmp_path / "c"
    shutil.copytree(EXAMPLE, d, ignore=shutil.ignore_patterns("gateway"))
    (d / "controller.yaml").write_text(yaml.safe_dump(controller), encoding="utf-8")
    doc = yaml.safe_load((d / "gateway.yml").read_text(encoding="utf-8"))
    if homes is not None:
        doc["controller"]["homes"] = homes
    (d / "gateway.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return gw.load_spec(d / "gateway.yml")


def test_a_backend_without_a_home_a_stray_home_and_a_duplicate_are_refused(tmp_path):
    ctl = {
        "backends": {
            "local": {"name": "vllm-a", "max_context": 131072},
            "additional": [{"name": "vllm-a", "max_context": 131072}, {"name": "vllm-b"}],
        }
    }
    problems = ah.controller_problems(_with(tmp_path, ctl, {"vllm-a": "homes/vllm-a",
                                                            "vllm-x": "homes/vllm-b"}))  # fmt: skip
    text = "\n".join(problems)
    assert "controller backend vllm-a is declared twice" in text
    assert "vllm-b (backends.additional[1]): no HERMES_HOME" in text
    assert "controller.homes.vllm-x: names no backend" in text


def test_a_missing_max_context_and_a_missing_home_file_are_refused(tmp_path):
    ctl = {"backends": {"local": {"name": "vllm-a"}, "local_fallback": {"name": "vllm-b",
                                                                         "max_context": 65536}}}  # fmt: skip
    spec = _with(tmp_path, ctl)
    (spec.controller.homes["vllm-b"] / "config.yaml").unlink()
    text = "\n".join(ah.controller_problems(spec))
    assert "max_context None differs from mdl:main-reasoner-a's max_context_tokens 131072" in text
    assert "cannot read" in text and "vllm-b" in text


def test_the_cloud_entry_is_not_a_gateway_backend_and_no_local_one_is_refused(tmp_path):
    spec = _with(tmp_path, {"backends": {"cloud": {"name": "cloud-fallback"}}})
    assert ah.controller_problems(spec)[0].endswith("declares no local backend")


@pytest.mark.parametrize(
    ("block", "words"),
    [
        ({"homes": {}}, "controller.config"),
        ({"config": "controller.yaml", "extra": 1}, "controller takes config"),
        ({"config": "controller.yaml", "homes": ["x"]}, "controller.homes"),
    ],
)
def test_a_bad_controller_block_is_a_spec_error(tmp_path, block, words):
    d = tmp_path / "s"
    shutil.copytree(EXAMPLE, d, ignore=shutil.ignore_patterns("gateway"))
    doc = yaml.safe_load((d / "gateway.yml").read_text(encoding="utf-8"))
    doc["controller"] = block
    (d / "gateway.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(gw.GatewaySpecError) as exc:
        gw.load_spec(d / "gateway.yml")
    assert any(words in p for p in exc.value.problems), exc.value.problems


# ---------------------------------------------------------------- homes (A-14)
def test_the_pass_homes_pass_and_every_fail_home_fails(capsys):
    passing = sorted(str(p) for p in (HOMES / "pass").iterdir())
    assert hnx(["gen", "gateway", "homes", "--roles", str(ROLES), *passing]) == 0
    assert "2 home(s) name no IP address" in capsys.readouterr().out
    for home in sorted((HOMES / "fail").iterdir()):
        assert hnx(["gen", "gateway", "homes", "--roles", str(ROLES), str(home)]) == 1, home
        err = capsys.readouterr().err
        assert err.count("homes: ") == 1, (home.name, err)
        want = "IP address" if home.name.startswith("ip") else "engine model id 'example-27b'"
        assert want in err, (home.name, err)


def test_a_missing_home_and_an_unreadable_role_table_are_not_a_pass(tmp_path, capsys):
    assert hnx(["gen", "gateway", "homes", "--roles", str(ROLES), str(tmp_path / "none")]) == 1
    assert "cannot read" in capsys.readouterr().err
    bad = tmp_path / "roles.json"
    bad.write_text("{}", encoding="utf-8")
    assert hnx(["gen", "gateway", "homes", "--roles", str(bad), str(HOMES / "pass")]) == 2


V4A = "192.0.2.10"  # no-raw-endpoint: allow documentation address (RFC 5737) under test
V4B = "198.51.100.7"  # no-raw-endpoint: allow documentation address (RFC 5737) under test
V4C = "203.0.113.9"  # no-raw-endpoint: allow documentation address (RFC 5737) under test
V6 = "2001:db8::5"  # documentation address (RFC 3849) under test
LOOP = "127.0.0.1"  # no-raw-endpoint: allow loopback is an address too


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("https://llm-gateway.example.internal/v1", []),
        (f"http://{V4A}:8000/v1", [V4A]),
        (f"http://{V4B}/v1", [V4B]),
        (f"http://[{V6}]:8000/v1", [V6]),
        (V6, [V6]),
        (f"engine at {V4C} today", [V4C]),
        (f"{LOOP}:8000", [LOOP]),
        ("main-reasoner-a", []),
        ("svc:vllm-a", []),
        ("1.4", []),
    ],
)
def test_ip_literals(text, found):
    assert ah.ip_literals(text) == found


def test_engine_model_ids_are_bindings_and_store_names_never_role_aliases():
    table = RoleTable.from_dict(
        {
            "roles": {
                "main-reasoner-a": {
                    "tier": "large",
                    "bindings": [{"backend": "svc:vllm-a", "model_id": "example-27b"}],
                },
                # a role spelled like a model id stays a role: a home must be able to name it
                "example-4b": {
                    "tier": "fast",
                    "bindings": [{"backend": "svc:vllm-b", "model_id": "example-4b"}],
                },
            }
        }
    )
    store = json.loads((ROOT / "examples" / "model-serving" / "model_store.json").read_text())
    ids = ah.engine_model_ids(table, store)
    assert "example-27b" in ids and "example-4b" not in ids
    assert "example-org/example-27b-fp8" in ids  # a hub repository an engine loads directly
    assert not set(table.roles) & ids
