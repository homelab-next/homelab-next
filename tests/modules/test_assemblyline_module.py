# SPDX-License-Identifier: Apache-2.0
"""modules/assemblyline (scaffold, ADR-0052): the manifest and the role's own rules, with no engine."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "assemblyline"
ROLE = MODULE / "roles" / "assemblyline"
PIN = re.compile(r"^[^@:]+(/[^@:]+)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}\Z")


def _defaults() -> dict:
    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())


def test_every_image_is_pinned_by_tag_and_digest_and_the_five_share_one_release():
    d = _defaults()
    images = {k: v for k, v in d.items() if k.endswith("_image")}
    assert len(images) == 7
    assert all(PIN.match(v) for v in images.values()), images
    product = [d[f"assemblyline_{n}_image"] for n in ("core", "rust", "ui", "socketio", "frontend")]
    assert len({v.split("@")[0].rsplit(":", 1)[1] for v in product}) == 1


def test_no_default_is_a_secret_or_an_appliance_default_password():
    text = (ROLE / "defaults" / "main.yml").read_text()
    for bad in ("password_123", "password_456", "password_789", "kb_password_456"):
        assert bad not in text
    refs = [v for k, v in _defaults().items() if k.endswith("_login_ref") or k.endswith("_key_ref")]
    assert len(refs) == 4 and all("/assemblyline/" in "/" + r.split(":", 1)[1] for r in refs)


def test_the_spec_renders_the_product_containers_and_nothing_privileged():
    task = yaml.safe_load((ROLE / "tasks" / "app.yml").read_text())[0]["ansible.builtin.set_fact"]
    services = task["assemblyline_app"]["compose_app_spec"]["services"]
    assert {"elasticsearch", "redis", "dispatcher", "ingester", "service_server", "ui"} <= set(
        services
    )
    assert not any("privileged" in s or "docker.sock" in str(s) for s in services.values())
    assert all("healthcheck" in s for s in services.values())


def test_manifest_forbids_egress_and_declares_the_slot_and_the_data():
    m = yaml.safe_load((MODULE / "module.yml").read_text())
    assert m["egress"] == "none"
    assert "file-analysis" in m["provides"]["slots"]
    assert m["requires"]["hosts"][0]["kind"] == "vm"
    assert m["data"][0]["export"]["via"] == "role:assemblyline"
    row = yaml.safe_load((MODULE / "registry" / "services.yml").read_text())["services"]
    assert "public_hostname" not in row["file-analysis"]


def test_the_scaffold_refuses_to_start_and_its_exports_fail_closed():
    assert "ansible.builtin.fail" in (ROLE / "tasks" / "main.yml").read_text()
    for hook in ("export", "backup", "restore"):
        assert "ansible.builtin.fail" in (ROLE / "tasks" / f"{hook}.yml").read_text()


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
