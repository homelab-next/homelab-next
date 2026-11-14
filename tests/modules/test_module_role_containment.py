# SPDX-License-Identifier: Apache-2.0
"""A real module's roles (``contributes.roles``: a directory ``roles/<name>``) load, and what the
containment check exists for is still refused: a path that leaves the module, a symbolic link on
the way to a role or anywhere inside the ``roles/`` tree (a role runs as root), a special file or
a hard link in it, an entry the manifest does not contribute, a tree too large or too deep, and a
lifecycle playbook that is not a contained regular file.

Before this, the check asked every contributed path to be a regular file, so a public or overlay
module that shipped the role directory it names failed ``hnx modules check`` with
``roles/<name>: not a regular file in the module``; only the fixture root's exemption hid it."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
MID = "demo-relay"

MANIFEST = {
    "manifest_version": "1.0",
    "id": MID,
    "kind": "provider",
    "title": "Exposure management on Demo Relay",
    "description": "A module that ships its role and playbook (fictional).",
    "owner": "platform-team",
    "author": "agent:example-builder",
    "status": "draft",
    "version": "0.1.0",
    "origin": {"kind": "in-tree"},
    "product": {"name": "demo-relay", "display": "Demo Relay", "version": "1.0.0"},
    "licence": {"kind": "trial", "expires": "2027-03-31", "renewal": "the slot is swapped"},
    "requires": {
        "capabilities": [{"cap": "cap:secrets", "version": "1.0", "purpose": "reads by name"}],
        "hosts": [
            {
                "role": "engine",
                "kind": "vm",
                "footprint": {"cpu": 1, "memory_mb": 512, "disk_gb": 10},
                "roles": ["role:demo_relay"],
                "purpose": "runs it",
            }
        ],
    },
    "provides": {
        "slots": {
            "exposure-management": {
                "formats": [{"format": "sarif", "version": "2.1.0"}],
                "adapter": "hnx_modules.demo_relay.exposure_management:make",
                "provisional": True,
                "reason": "the slot has no contract yet",
            }
        }
    },
    "contributes": {"roles": [{"file": "roles/demo_relay"}]},
    "lifecycle": {"install": {"playbook": "playbooks/install.yml"}},
}


def module(tmp_path: Path, where: str = "public") -> Path:
    """A minimal real module (public ``modules/`` or an overlay's ``lab/modules/``) that ships
    ``roles/demo_relay/`` and its install playbook."""
    base = tmp_path / ("modules" if where == "public" else "overlay/lab/modules")
    d = base / MID
    (d / "roles" / "demo_relay" / "tasks").mkdir(parents=True)
    (d / "roles" / "demo_relay" / "tasks" / "main.yml").write_text("- {}\n")
    (d / "roles" / "demo_relay" / "defaults").mkdir()
    (d / "roles" / "demo_relay" / "defaults" / "main.yml").write_text("demo_relay_port: 1\n")
    (d / "playbooks").mkdir()
    (d / "playbooks" / "install.yml").write_text("- hosts: all\n  roles: [demo_relay]\n")
    doc = (
        MANIFEST
        if where == "public"
        else {**MANIFEST, "origin": {"kind": "git", "url": "https://example.internal/m.git"}}
    )
    (d / "module.yml").write_text(yaml.safe_dump(doc))
    return d


def problems(tmp_path: Path, where: str = "public") -> list[str]:
    if where == "public":
        tree, found = ld.discover(public=tmp_path / "modules")
    else:
        tree, found = ld.discover(overlay=tmp_path / "overlay")
    assert found == []
    report = ld.check(tree, slots=SLOTS, roles={}, in_tree_roots=(tmp_path / "modules",))
    return [str(p) for p in report.problems]


def edit(d: Path, change) -> None:
    doc = yaml.safe_load((d / "module.yml").read_text())
    change(doc)
    (d / "module.yml").write_text(yaml.safe_dump(doc))


# ----------------------------------------------------------------------------- the blocker


@pytest.mark.parametrize("where", ["public", "overlay"])
def test_a_real_module_that_ships_its_role_directory_loads(tmp_path, where):
    module(tmp_path, where)
    got = problems(tmp_path, where)
    assert not [p for p in got if "roles/" in p or "playbooks/" in p], got
    if where == "public":
        assert got == []


def test_a_role_named_with_its_directory_slash_loads(tmp_path):
    d = module(tmp_path)
    edit(d, lambda doc: doc["contributes"].update(roles=[{"file": "roles/demo_relay/"}]))
    assert problems(tmp_path) == []


# ----------------------------------------------------------------------------- still refused


def test_a_role_outside_roles_is_refused(tmp_path):
    d = module(tmp_path)
    (d / "elsewhere" / "demo_relay").mkdir(parents=True)
    edit(d, lambda doc: doc["contributes"].update(roles=[{"file": "elsewhere/demo_relay"}]))
    got = problems(tmp_path)
    assert any(
        p.startswith(f"{MID}: elsewhere/demo_relay: a role is the directory roles/<name>")
        for p in got
    ), got


@pytest.mark.parametrize("rel", ["roles/demo_relay/tasks", "roles/../demo_relay", "roles"])
def test_a_role_path_that_is_not_roles_name_is_refused(tmp_path, rel):
    d = module(tmp_path)
    doc = {**MANIFEST, "contributes": {"roles": [{"file": rel}]}}
    got = ld._role_problems(doc, d)
    assert any(p.startswith(f"{rel}: a role is the directory roles/<name>") for p in got), got


def test_a_role_directory_that_is_a_symlink_out_of_the_module_is_refused(tmp_path):
    d = module(tmp_path)
    outside = tmp_path / "outside-role"
    (outside / "tasks").mkdir(parents=True)
    (outside / "tasks" / "main.yml").write_text("- {}\n")
    role = d / "roles" / "demo_relay"
    for p in sorted(role.rglob("*"), reverse=True):
        p.rmdir() if p.is_dir() else p.unlink()
    role.rmdir()
    role.symlink_to(outside, target_is_directory=True)
    assert f"{MID}: roles/demo_relay: reached through a symbolic link" in problems(tmp_path)


def test_a_roles_directory_that_is_a_symlink_is_refused(tmp_path):
    d = module(tmp_path)
    (d / "roles").rename(tmp_path / "real-roles")
    (d / "roles").symlink_to(tmp_path / "real-roles", target_is_directory=True)
    assert f"{MID}: roles: reached through a symbolic link" in problems(tmp_path)


@pytest.mark.parametrize(
    "plant, name",
    [
        (lambda t, out: (t / "pw.yml").symlink_to("/etc/passwd"), "tasks/pw.yml"),
        (lambda t, out: (t / "inner.yml").symlink_to("main.yml"), "tasks/inner.yml"),
        (lambda t, out: (t / "dir").symlink_to(out, target_is_directory=True), "tasks/dir"),
        (lambda t, out: (t / "dangling.yml").symlink_to(out / "missing"), "tasks/dangling.yml"),
    ],
    ids=["to-an-outside-file", "to-a-sibling", "to-a-directory", "dangling"],
)
def test_a_symlink_anywhere_inside_a_role_is_refused(tmp_path, plant, name):
    d = module(tmp_path)
    out = tmp_path / "outside"
    out.mkdir()
    plant(d / "roles" / "demo_relay" / "tasks", out)
    want = f"{MID}: roles/demo_relay/{name}: a symbolic link (a role runs as root; ship the file itself)"
    assert want in problems(tmp_path)


def test_a_symlink_deep_in_a_role_is_found(tmp_path):
    d = module(tmp_path)
    deep = d / "roles" / "demo_relay" / "files" / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "x").symlink_to("/etc/shadow")
    want = f"{MID}: roles/demo_relay/files/a/b/x: a symbolic link"
    assert any(p.startswith(want) for p in problems(tmp_path))


def test_a_hard_link_or_special_file_in_a_role_is_refused(tmp_path):
    d = module(tmp_path)
    t = d / "roles" / "demo_relay" / "tasks"
    outside = tmp_path / "outside.yml"
    outside.write_text("- {}\n")
    os.link(outside, t / "linked.yml")
    assert (
        f"{MID}: roles/demo_relay/tasks/linked.yml: a hard link (it may alias a file outside "
        "the module)" in problems(tmp_path)
    )
    (t / "linked.yml").unlink()
    os.mkfifo(t / "pipe")
    assert f"{MID}: roles/demo_relay/tasks/pipe: not a regular file or a directory" in problems(
        tmp_path
    )


def test_a_missing_or_file_shaped_role_is_refused(tmp_path):
    d = module(tmp_path)
    role = d / "roles" / "demo_relay"
    for p in sorted(role.rglob("*"), reverse=True):
        p.rmdir() if p.is_dir() else p.unlink()
    role.rmdir()
    assert f"{MID}: roles/demo_relay: not a role directory in the module" in problems(tmp_path)
    role.write_text("- {}\n")  # what the check used to ask for
    assert f"{MID}: roles/demo_relay: not a role directory in the module" in problems(tmp_path)


def test_an_entry_under_roles_the_manifest_does_not_contribute_is_refused(tmp_path):
    d = module(tmp_path)
    (d / "roles" / "stray").mkdir()
    (d / "roles" / "linked").symlink_to("/", target_is_directory=True)
    got = problems(tmp_path)
    assert any(p.startswith(f"{MID}: roles/stray: not a contributed role") for p in got), got
    assert any(p.startswith(f"{MID}: roles/linked: not a contributed role") for p in got), got


def test_a_roles_tree_too_large_or_too_deep_is_refused_not_cut_short(tmp_path, monkeypatch):
    d = module(tmp_path)
    monkeypatch.setattr(ld, "MAX_ROLE_ENTRIES", 3)
    assert f"{MID}: roles: more than 3 entries" in problems(tmp_path)
    monkeypatch.setattr(ld, "MAX_ROLE_ENTRIES", 5_000)
    monkeypatch.setattr(ld, "MAX_ROLE_DEPTH", 3)
    (d / "roles" / "demo_relay" / "files" / "a" / "b").mkdir(parents=True)
    got = problems(tmp_path)
    assert f"{MID}: roles/demo_relay/files/a: nested more than 3 levels" in got, got


def test_a_loose_file_beside_the_roles_is_refused(tmp_path):
    d = module(tmp_path)
    (d / "roles" / "README.md").write_text("roles\n")
    got = problems(tmp_path)
    assert any(p.startswith(f"{MID}: roles/README.md: not a contributed role") for p in got), got


def test_a_huge_directory_is_refused_without_listing_all_of_it(tmp_path, monkeypatch):
    d = module(tmp_path)
    many = d / "roles" / "demo_relay" / "files"
    many.mkdir()
    for i in range(50):
        (many / f"f{i}").write_text("")
    monkeypatch.setattr(ld, "MAX_ROLE_ENTRIES", 10)
    assert f"{MID}: roles: more than 10 entries" in problems(tmp_path)


def test_a_role_file_is_never_read_or_followed(tmp_path, monkeypatch):
    d = module(tmp_path)
    (d / "roles" / "demo_relay" / "tasks" / "pw.yml").symlink_to("/etc/passwd")
    opened: list[str] = []
    real = os.open
    monkeypatch.setattr(os, "open", lambda p, *a, **k: opened.append(str(p)) or real(p, *a, **k))
    problems(tmp_path)
    assert not [p for p in opened if "roles" in p or "passwd" in p], opened


@pytest.mark.parametrize("how", ["symlink", "missing", "directory"])
def test_a_lifecycle_playbook_must_be_a_contained_regular_file(tmp_path, how):
    d = module(tmp_path)
    book = d / "playbooks" / "install.yml"
    book.unlink()
    if how == "symlink":
        (tmp_path / "evil.yml").write_text("- hosts: all\n")
        book.symlink_to(tmp_path / "evil.yml")
        want = "reached through a symbolic link"
    elif how == "directory":
        book.mkdir()
        want = "not a regular file in the module"
    else:
        want = "not a regular file in the module"
    assert f"{MID}: playbooks/install.yml: {want}" in problems(tmp_path)


def test_a_fixture_module_that_ships_a_roles_tree_is_checked_too(tmp_path):
    fixtures = tmp_path / "fixtures"
    d = module(tmp_path)
    d.rename(fixtures / MID) if fixtures.exists() else (fixtures.mkdir(), d.rename(fixtures / MID))
    (fixtures / MID / "roles" / "demo_relay" / "tasks" / "pw.yml").symlink_to("/etc/passwd")
    tree, found = ld.discover(fixtures=fixtures)
    assert found == []
    report = ld.check(tree, slots=SLOTS, roles={}, in_tree_roots=(fixtures,))
    assert any("roles/demo_relay/tasks/pw.yml: a symbolic link" in str(p) for p in report.problems)
