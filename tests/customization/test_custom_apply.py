# SPDX-License-Identifier: Apache-2.0
"""The applier: plan content, determinism, fail-closed, conflicts and the no-core-edit rule."""

from __future__ import annotations

import hashlib
import json

import pytest
from cust_helpers import TODAY, load_one, make_doc, write_custom

from homelabnext.customization import build_plan, write_plan


def tree_digest(root):
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            h.update(p.relative_to(root).as_posix().encode() + p.read_bytes())
    return h.hexdigest()


def plan_for(tmp_path, uni, docs, enabled=None):
    for i, (doc, files) in enumerate(docs):
        write_custom(tmp_path, f"c{i}", doc, files)
    return build_plan(load_one(tmp_path), uni, TODAY, enabled)


def hook_doc(**kw):
    base = {
        "id": "custom:hook-one",
        "kind": "hook",
        "action": {
            "role": "example_service",
            "entry_point": "health",
            "phase": "post",
            "tasks_file": "t.yml",
        },
    }
    base.update(kw)
    return make_doc(**base), {"t.yml": "- ansible.builtin.debug: {msg: extra}\n"}


def test_override_plan_and_resolved_view(tmp_path, uni):
    plan = plan_for(tmp_path, uni, [(make_doc(), None)])
    assert plan["ok"] and plan["schema"] == "hnx.customization.plan/1"
    assert plan["resolved"]["role_vars"] == {
        "example_service": {"example_service_listen_port": 9090}
    }
    (item,) = plan["items"]
    assert item["extension_points"] == ["var:example_service.example_service_listen_port"]
    assert item["changes"] == [
        {"set_var": "example_service.example_service_listen_port", "value": 9090}
    ]


def test_hook_overlay_and_profile_resolution(tmp_path, uni):
    h, hf = hook_doc()
    ov = make_doc(
        id="custom:overlay-one",
        kind="patch-overlay",
        action={
            "role": "example_service",
            "template": "config.yml.j2",
            "overlay": "o.j2",
            "mode": "append",
        },
    )
    pr = make_doc(
        id="custom:profile-one",
        kind="profile",
        scope={"hosts": ["mon-core"]},
        action={
            "profile": "extra",
            "tasks": [{"name": "Do extra", "file": "p.yml"}],
            "vars": {"extra_flag": True},
        },
    )
    plan = plan_for(
        tmp_path, uni, [(h, hf), (ov, {"o.j2": "x: 1\n"}), (pr, {"p.yml": "- name: x\n"})]
    )
    assert plan["ok"], plan["findings"]
    r = plan["resolved"]
    assert r["hooks"]["example_service"]["health"]["post"] == ["custom:hook-one:t.yml"]
    (o,) = r["template_overlays"]["example_service"]["config.yml.j2"]
    assert o["sha256"] == hashlib.sha256(b"x: 1\n").hexdigest()
    assert r["profiles"]["extra"]["hosts"] == ["mon-core"]
    assert [i["kind"] for i in plan["items"]] == ["patch-overlay", "hook", "profile"]


def test_registry_patch_valid_and_invalid(tmp_path, uni):
    good = make_doc(
        id="custom:reg-good",
        kind="registry-patch",
        action={"service": "edge-proxy", "set": {"tls": "internal"}},
    )
    plan = plan_for(tmp_path / "g", uni, [(good, None)])
    assert plan["ok"], plan["findings"]
    (chg,) = plan["resolved"]["registry_changes"]
    assert chg["before"] == "public" and chg["after"] == "internal"
    bad = make_doc(
        id="custom:reg-bad",
        kind="registry-patch",
        action={"service": "edge-proxy", "set": {"port": 70000}},
    )
    plan = plan_for(tmp_path / "b", uni, [(bad, None)])
    assert not plan["ok"] and plan["resolved"]["registry_changes"] == []
    assert any("patched registry invalid" in f["message"] for f in plan["findings"])
    assert plan["items"] == []  # fail closed: nothing from the rejected patch is planned


def test_registry_patch_does_not_mutate_loaded_registry(tmp_path, uni):
    before = json.dumps(uni.registry, sort_keys=True)
    good = make_doc(
        id="custom:reg-good",
        kind="registry-patch",
        action={"service": "edge-proxy", "set": {"tls": "internal"}},
    )
    plan_for(tmp_path, uni, [(good, None)])
    assert json.dumps(uni.registry, sort_keys=True) == before


def test_deterministic_regardless_of_load_order(tmp_path, uni):
    docs = [
        (
            make_doc(
                id=f"custom:v-{n}",
                action={"role": "example_service", "vars": {f"example_service_{v}": 1}},
            ),
            None,
        )
        for n, v in [("a", "listen_port"), ("b", "health_path"), ("c", "version")]
    ]
    p1 = plan_for(tmp_path / "x", uni, docs)
    p2 = plan_for(tmp_path / "y", uni, list(reversed(docs)))
    assert json.dumps(p1, sort_keys=True) == json.dumps(p2, sort_keys=True)
    assert [i["id"] for i in p1["items"]] == ["custom:v-a", "custom:v-b", "custom:v-c"]


def test_conflict_excludes_both_and_fails(tmp_path, uni):
    a = make_doc(id="custom:one")
    b = make_doc(
        id="custom:two",
        action={"role": "example_service", "vars": {"example_service_listen_port": 7}},
    )
    plan = plan_for(tmp_path, uni, [(a, None), (b, None)])
    assert not plan["ok"]
    assert plan["conflicts"] == [
        {
            "extension_point": "var:example_service.example_service_listen_port",
            "ids": ["custom:one", "custom:two"],
        }
    ]
    assert plan["resolved"]["role_vars"] == {} and plan["items"] == []


def test_two_hooks_same_point_conflict_but_different_phase_do_not(tmp_path, uni):
    h1, f1 = hook_doc(id="custom:h1")
    h2, f2 = hook_doc(id="custom:h2")
    assert plan_for(tmp_path / "a", uni, [(h1, f1), (h2, f2)])["conflicts"]
    h3, f3 = hook_doc(id="custom:h3")
    h3["action"]["phase"] = "pre"
    assert not plan_for(tmp_path / "b", uni, [(h1, f1), (h3, f3)])["conflicts"]


def test_expired_customization_is_not_applied(tmp_path, uni):
    plan = plan_for(tmp_path, uni, [(make_doc(created="2025-01-01", review_by="2025-06-01"), None)])
    assert not plan["ok"] and plan["items"] == []
    assert any(f["code"] == "CU008" for f in plan["findings"])


def test_invalid_schema_never_reaches_resolved_view(tmp_path, uni):
    plan = plan_for(
        tmp_path,
        uni,
        [
            (make_doc(reason=None), None),
            (
                make_doc(
                    id="custom:fine",
                    action={
                        "role": "example_service",
                        "vars": {"example_service_version": "2.0.0"},
                    },
                ),
                None,
            ),
        ],
    )
    assert not plan["ok"]
    assert list(plan["resolved"]["role_vars"]["example_service"]) == ["example_service_version"]


def test_optional_needs_enabling_and_narrows_hosts(tmp_path, uni):
    pr = make_doc(
        id="custom:opt",
        kind="profile",
        optional=True,
        scope={"capabilities": ["cap:monitoring"]},
        action={"profile": "opt", "tasks": [{"name": "Do it", "file": "p.yml"}]},
    )
    files = {"p.yml": "- name: x\n"}
    off = plan_for(tmp_path / "off", uni, [(pr, files)])
    assert off["items"] == [] and off["inactive_optional"] == ["custom:opt"]
    on = plan_for(tmp_path / "on", uni, [(pr, files)], enabled={"custom:opt": ["mon-core"]})
    assert on["ok"] and on["resolved"]["profiles"]["opt"]["hosts"] == ["mon-core"]


def test_applier_never_modifies_core(tmp_path, uni, repo_root):
    before = {d: tree_digest(repo_root / d) for d in ("ansible", "schemas", "examples", "docs")}
    h, hf = hook_doc()
    ov = make_doc(
        id="custom:overlay-one",
        kind="patch-overlay",
        action={
            "role": "example_service",
            "template": "config.yml.j2",
            "overlay": "o.j2",
            "mode": "replace",
        },
    )
    reg = make_doc(
        id="custom:reg",
        kind="registry-patch",
        action={"service": "edge-proxy", "set": {"tls": "internal"}},
    )
    plan = plan_for(tmp_path, uni, [(make_doc(), None), (h, hf), (ov, {"o.j2": "x"}), (reg, None)])
    write_plan(plan, tmp_path / "plan.json", uni)
    after = {d: tree_digest(repo_root / d) for d in before}
    assert before == after


@pytest.mark.parametrize(
    "target", ["ansible/roles/example_service/defaults/main.yml", "schemas/platform/plan.json"]
)
def test_write_plan_refuses_core_paths(tmp_path, uni, repo_root, target):
    plan = plan_for(tmp_path, uni, [(make_doc(), None)])
    path = repo_root / target
    existed = path.exists()
    with pytest.raises(PermissionError):
        write_plan(plan, path, uni)
    assert path.exists() == existed


def test_path_traversal_hook_is_rejected_and_unplanned(tmp_path, uni):
    evil = make_doc(
        id="custom:evil",
        kind="hook",
        action={
            "role": "example_service",
            "entry_point": "main",
            "phase": "pre",
            "tasks_file": "../../../ansible/roles/example_service/tasks/main.yml",
        },
    )
    plan = plan_for(tmp_path, uni, [(evil, None)])
    assert not plan["ok"] and plan["resolved"]["hooks"] == {}


def test_unknown_extension_point_kind_cannot_be_expressed(tmp_path, uni):
    odd = make_doc(
        id="custom:odd",
        kind="edit-core-file",
        action={"file": "ansible/roles/example_service/tasks/main.yml", "content": "x"},
    )
    plan = plan_for(tmp_path, uni, [(odd, None)])
    assert not plan["ok"] and plan["items"] == []
