# SPDX-License-Identifier: Apache-2.0
"""``loader.read_contained``: a path named by a file a change controls stays inside a root the
caller gives (default: the working directory when the base is in it, else the base); nothing is
discovered from the base, so a planted repository layout cannot widen the root."""

from __future__ import annotations

import os
import subprocess

import pytest

from homelabnext.modules import loader as ld


def _plant_bare_repo(d):
    """The files of a bare repository whose worktree is ``/``: none named ``.git``, so a change
    could commit them, and git's discovery would take ``d`` as a repository."""
    (d / "HEAD").write_text("ref: refs/heads/main\n")
    (d / "config").write_text("[core]\n\tbare = false\n\tworktree = /\n")
    (d / "objects").mkdir()
    (d / "refs").mkdir()
    (d / "refs" / "heads").mkdir()


def test_a_planted_bare_repository_cannot_widen_the_root(tmp_path, monkeypatch):
    spec = tmp_path / "spec"
    spec.mkdir()
    _plant_bare_repo(spec)
    escape = "../" * 12 + "etc/passwd"
    with pytest.raises(ld.Unreadable, match="outside the root"):
        ld.read_contained(spec, escape)
    # the working directory as the root (a spec under it) bounds it the same way
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ld.Unreadable, match="outside the root"):
        ld.read_contained("spec", escape)


def test_no_root_is_discovered_through_git(tmp_path, monkeypatch):
    def no_git(*a, **k):
        raise AssertionError("read_contained ran a process")

    monkeypatch.setattr(subprocess, "run", no_git)
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.json").write_text("{}")
    assert ld.read_contained(tmp_path / "a", "f.json") == b"{}"


def test_the_default_root_is_the_working_directory_when_the_base_is_in_it(tmp_path, monkeypatch):
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "t.json").write_text("{}")
    base = tmp_path / "compose" / "cfg"
    base.mkdir(parents=True)
    (tmp_path / ".git").mkdir()  # the working directory is a checkout
    monkeypatch.chdir(tmp_path)
    assert ld.containment_root(base) == tmp_path
    assert ld.read_contained(base, "../../schemas/t.json") == b"{}"
    # outside the working directory, the base is its own root
    other = tmp_path.parent / f"{tmp_path.name}-other"
    other.mkdir()
    assert ld.containment_root(other) == other


def test_a_link_on_the_path_is_refused_by_the_walk(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "t.json").write_text("{}")
    os.symlink(real, tmp_path / "linked")
    os.symlink(real / "t.json", tmp_path / "file-link.json")
    for rel in ("linked/t.json", "file-link.json"):
        with pytest.raises(ld.Unreadable, match="a symbolic link on its path"):
            ld.read_contained(tmp_path, rel, tmp_path)
    with pytest.raises(ld.Unreadable, match="an absolute path"):
        ld.read_contained(tmp_path, str(real / "t.json"), tmp_path)


def test_a_working_directory_that_is_no_checkout_is_not_the_root(tmp_path, monkeypatch):
    base = tmp_path / "compose" / "cfg"
    base.mkdir(parents=True)
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "t.json").write_text("{}")
    monkeypatch.chdir(tmp_path)  # no .git here, and outside this package's checkout
    assert ld.containment_root(base) == base
    with pytest.raises(ld.Unreadable, match="outside the root"):
        ld.read_contained(base, "../../schemas/t.json")


def test_a_filesystem_root_is_refused_as_the_root(tmp_path, monkeypatch):
    (tmp_path / "t.json").write_text("{}")
    with pytest.raises(ld.Unreadable, match="is a filesystem root"):
        ld.read_contained(tmp_path, "t.json", "/")
    monkeypatch.chdir("/")
    monkeypatch.setattr(ld.os.path, "lexists", lambda p: True)  # as if / held a .git entry
    with pytest.raises(ld.Unreadable, match="is a filesystem root"):
        ld.read_contained(tmp_path, "t.json")


def test_a_root_that_is_a_symbolic_link_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "t.json").write_text("{}")
    (tmp_path / "linked").symlink_to(real, target_is_directory=True)
    with pytest.raises(ld.Unreadable, match="a symbolic link on its path"):
        ld.read_contained(tmp_path / "linked", "t.json", tmp_path / "linked")


def test_this_package_s_own_checkout_is_a_default_root_without_git(tmp_path, monkeypatch):
    # a `git archive` export has no .git: the package's verified checkout still bounds its specs
    own = tmp_path / "export"
    base = own / "compose" / "cfg"
    base.mkdir(parents=True)
    monkeypatch.setattr(ld.paths, "checkout_root", lambda: own)
    monkeypatch.chdir(tmp_path)
    assert ld.containment_root(base) == own
