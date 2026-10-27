# SPDX-License-Identifier: Apache-2.0
"""A swap's model evidence read from the repository (``homelabnext.modules.swap_evidence``,
``hnx modules swap-check``): the role table before from the base commit, the one after from the
working tree, the store and the reports from where the repository keeps them; a table missing at
the base, a symbolic link at either end and a doctored table after are refused."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext import paths
from homelabnext.golden import pins as gp
from homelabnext.golden.canary import benign_model
from homelabnext.models import store as st
from homelabnext.modules import cli as mcli
from homelabnext.modules import swap as ms
from homelabnext.modules import swap_evidence as se
from homelabnext.registry.models import RoleTable

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "schemas/platform/examples/module_swap.inference-rebind.json"
ROLES = paths.example_file("model_roles.json")
STORE_FILE = paths.example_file("model-serving", "model_store.json")
STORE = st.load(STORE_FILE)
BEFORE = RoleTable.load(ROLES)
#: the store entry serving the role's own model id under other weights (found, not named)
(ENTRY,) = (
    e
    for e in STORE.entries.values()
    if e.served_model_name == BEFORE.get("fast-classifier").bindings[0].model_id
)


def _rebound_doc(digest: str = ENTRY.digest) -> dict:
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    doc["roles"]["fast-classifier"]["bindings"] = [
        {"backend": "svc:inference", "model_id": ENTRY.served_model_name,
         "version": ENTRY.revision, "digest": digest}
    ]  # fmt: skip
    return doc


AFTER = RoleTable.from_dict(_rebound_doc())


def _live(role, binding):
    """A stand-in for a live canary run, recorded as live: the check reads a report's shape."""
    return benign_model, "live"


@pytest.fixture(scope="module")
def report() -> dict:
    return gp.run_eval(
        AFTER, gp.DEFAULT_SUITES, gp.fake_factory, model_name="fake-golden", canary_factory=_live
    )


def _git(root: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def _commit(root: Path) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "c")


def _write(root: Path, rel: str, doc) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def repo(tmp_path, report) -> Path:
    """The base commit holds the shipped role table and store; the working tree rebinds
    ``mdl:fast-classifier`` to the store entry and keeps the live report for the table after."""
    root = tmp_path / "repo"
    (root / "examples" / "model-serving").mkdir(parents=True)
    shutil.copy(ROLES, root / se.ROLES)
    shutil.copy(STORE_FILE, root / se.STORE)
    _git(root, "init", "-q")
    _commit(root)
    _write(root, se.ROLES, _rebound_doc())
    _write(root, se.REPORTS[1], report)
    return root


def _swap(report: dict) -> dict:
    swap = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    swap["model_roles"][0]["evaluation"]["report"] = gp.report_digest(report)
    return swap


def test_the_tables_come_from_the_base_and_the_working_tree(repo, report):
    ev = se.from_git(repo, "HEAD")
    assert ev.before.pins() == BEFORE.pins()
    assert ev.after.pins() == AFTER.pins()
    assert ev.require_live and ev.store is not None
    assert gp.report_digest(report) in {gp.report_digest(r) for r in ev.reports}
    assert ms.model_role_problems(_swap(report), ev) == []


def test_a_table_missing_at_the_base_is_refused(tmp_path):
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "x.md").write_text("x\n")
    _git(root, "init", "-q")
    _commit(root)
    _write(root, se.ROLES, _rebound_doc())
    with pytest.raises(se.EvidenceError, match="is not in HEAD: the table before the swap"):
        se.from_git(root, "HEAD", store=None)


def test_a_base_that_is_no_commit_is_refused(repo):
    for base in ("", "no-such-ref", "HEAD~5"):
        with pytest.raises(se.EvidenceError, match="not a commit here"):
            se.from_git(repo, base)


def test_a_path_outside_the_repository_is_refused(repo):
    for rel in ("../model_roles.json", "/etc/hosts", ""):
        with pytest.raises(se.EvidenceError, match="not a path inside the repository"):
            se.read_base(repo, "HEAD", rel)


def test_the_working_tree_table_is_never_read_through_a_symbolic_link(repo, tmp_path):
    elsewhere = _write(tmp_path, "elsewhere.json", _rebound_doc())
    (repo / se.ROLES).unlink()
    (repo / se.ROLES).symlink_to(elsewhere)
    with pytest.raises(se.EvidenceError, match="a symbolic link on its path"):
        se.from_git(repo, "HEAD")


def test_a_directory_link_on_the_path_is_refused(repo, tmp_path):
    shutil.move(repo / "examples", tmp_path / "real")
    (repo / "examples").symlink_to(tmp_path / "real")
    with pytest.raises(se.EvidenceError, match="a symbolic link on its path"):
        se.read_head(repo, se.ROLES)


def test_a_symbolic_link_at_the_base_is_refused(tmp_path):
    root = tmp_path / "repo"
    _write(root, "real.json", json.loads(ROLES.read_text(encoding="utf-8")))
    (root / "examples").mkdir()
    (root / se.ROLES).symlink_to("../real.json")
    _git(root, "init", "-q")
    _commit(root)
    with pytest.raises(se.EvidenceError, match="at HEAD: a symbolic link"):
        se.read_base(root, "HEAD", se.ROLES)


def test_an_oversized_table_at_the_base_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    _write(root, se.ROLES, json.loads(ROLES.read_text(encoding="utf-8")))
    _git(root, "init", "-q")
    _commit(root)
    monkeypatch.setattr(se.ld, "MAX_BYTES", 64)
    with pytest.raises(se.EvidenceError, match="over 64 bytes"):
        se.read_base(root, "HEAD", se.ROLES)


def test_a_doctored_table_after_is_caught(repo, report):
    """The working tree claims other weights for the new binding than the report and the store
    evidence: the leg's pin no longer resolves, and the report is stale for the table."""
    _write(repo, se.ROLES, _rebound_doc(digest="sha256:" + "1" * 64))
    p = ms.model_role_problems(_swap(report), se.from_git(repo, "HEAD"))
    assert any("the new binding does not resolve in the role table after" in x for x in p)


def test_the_store_must_be_in_the_working_tree(repo):
    (repo / se.STORE).unlink()
    with pytest.raises(se.EvidenceError, match=r"model_store\.json: not in the working tree"):
        se.from_git(repo, "HEAD")
    assert se.from_git(repo, "HEAD", store=None).store is None


def test_the_policy_not_the_record_decides_live(repo, report):
    swap = _swap(report)
    swap["model_roles"][0]["evaluation"]["require_live"] = False
    assert se.from_git(repo, "HEAD").require_live is True
    assert ms.model_role_problems(swap, se.from_git(repo, "HEAD")) == []


# ------------------------------------------------------------------------------- the CLI


@pytest.fixture
def checkout(repo) -> Path:
    """The repo with the example modules, an incoming provider and the site the swap starts
    from, so ``hnx modules swap-check`` runs end to end."""
    shutil.copytree(ROOT / "examples" / "modules", repo / "examples" / "modules")
    (repo / "modules").mkdir()
    other = repo / "examples" / "modules" / "other-inference"
    shutil.copytree(repo / "examples" / "modules" / "example-inference", other)
    doc = yaml.safe_load((other / "module.yml").read_text(encoding="utf-8"))
    doc["id"] = "other-inference"
    (other / "module.yml").write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return repo


def _cli(root: Path, record: Path, capsys, *extra: str) -> tuple[int, dict | str]:
    rc = mcli.main(
        ["swap-check", str(record), "--root", str(root), "--examples", "--base", "HEAD",
         "--site", str(root / "examples/modules/sites/full.yml"), "--json", *extra]
    )  # fmt: skip
    out = capsys.readouterr()
    return rc, (json.loads(out.out) if out.out else out.err)


def test_the_cli_checks_a_rebind_end_to_end(checkout, report, capsys, tmp_path):
    record = _write(tmp_path, "swap.json", _swap(report))
    rc, out = _cli(checkout, record, capsys)
    assert (rc, out["problems"], out["evidence"]) == (0, [], True)


def test_the_cli_refuses_a_doctored_table_after(checkout, report, capsys, tmp_path):
    _write(checkout, se.ROLES, _rebound_doc(digest="sha256:" + "1" * 64))
    rc, out = _cli(checkout, _write(tmp_path, "swap.json", _swap(report)), capsys)
    assert rc == 1 and out["problems"]


def test_the_cli_refuses_an_unreadable_input(checkout, report, capsys, tmp_path):
    record = _write(tmp_path, "swap.json", _swap(report))
    (checkout / se.ROLES).unlink()
    (checkout / se.ROLES).symlink_to(_write(tmp_path, "elsewhere.json", _rebound_doc()))
    rc, err = _cli(checkout, record, capsys)
    assert rc == 2 and "a symbolic link on its path" in err
    link = tmp_path / "link.json"
    link.symlink_to(record)
    rc, err = _cli(checkout, link, capsys)
    assert rc == 2 and "a symbolic link" in err


def test_the_cli_refuses_a_record_the_schema_refuses(checkout, report, capsys, tmp_path):
    swap = _swap(report)
    del swap["to_module"]
    rc, out = _cli(checkout, _write(tmp_path, "swap.json", swap), capsys)
    assert rc == 1 and any(p.startswith("record: ") for p in out["problems"])
