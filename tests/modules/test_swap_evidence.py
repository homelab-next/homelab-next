# SPDX-License-Identifier: Apache-2.0
"""A swap's model evidence read from the repository (``homelabnext.modules.swap_evidence``,
``hnx modules swap-check`` and ``swap-gate``): the role table after from the working tree, and
everything that vouches for the new model (the table before, the store, the reports, the suites)
from the base commit, so a change cannot vouch for itself; a base that is not a commit, a table
missing at the base, a symbolic link at either end, a doctored table after and an uncovered
role-table change are refused."""

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
CANDIDATE = f"{se.EVALS}/fast-classifier.json"


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


def _git(root: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    r = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)
    return r.stdout.decode().strip()


def _commit(root: Path) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "c")
    return _git(root, "rev-parse", "HEAD")


def _write(root: Path, rel: str, doc) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


def _base_files(root: Path, *, store: bool = True) -> None:
    (root / "examples" / "model-serving").mkdir(parents=True, exist_ok=True)
    shutil.copy(ROLES, root / se.ROLES)
    if store:
        shutil.copy(STORE_FILE, root / se.STORE)
    for rel, src in zip(se.SUITES, gp.DEFAULT_SUITES, strict=True):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, root / rel)


@pytest.fixture
def repo(tmp_path, report) -> Path:
    """The base commit holds the shipped role table, the store and the live report for the table
    after (the vetting change); the working tree rebinds ``mdl:fast-classifier``."""
    root = tmp_path / "repo"
    _base_files(root)
    _write(root, CANDIDATE, report)
    _git(root, "init", "-q")
    _commit(root)
    _write(root, se.ROLES, _rebound_doc())
    return root


def _swap(report: dict) -> dict:
    swap = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    swap["model_roles"][0]["evaluation"]["report"] = gp.report_digest(report)
    return swap


def test_the_suites_are_the_golden_defaults():
    assert [Path(r).name for r in se.SUITES] == [p.name for p in gp.DEFAULT_SUITES]
    for rel, p in zip(se.SUITES, gp.DEFAULT_SUITES, strict=True):
        assert (ROOT / rel).read_bytes() == p.read_bytes()


def test_the_evidence_is_the_bases_and_the_table_after_the_working_trees(repo, report):
    ev = se.from_git(repo, "HEAD")
    assert ev.before.pins() == BEFORE.pins()
    assert ev.after.pins() == AFTER.pins()
    assert ev.require_live and ev.store is not None
    assert gp.report_digest(report) in {gp.report_digest(r) for r in ev.reports}
    assert ms.model_role_problems(_swap(report), ev) == []


def test_a_change_cannot_vouch_for_itself(tmp_path, report):
    """A forged live report and a doctored store in the working tree count for nothing: the base
    has neither the store entry nor the report, so the leg is refused."""
    root = tmp_path / "repo"
    _base_files(root)
    base_store = json.loads(STORE_FILE.read_text(encoding="utf-8"))
    del base_store["models"][ENTRY.id]
    _write(root, se.STORE, base_store)
    _git(root, "init", "-q")
    _commit(root)
    _write(root, se.ROLES, _rebound_doc())
    shutil.copy(STORE_FILE, root / se.STORE)  # the doctored store, with the entry
    _write(root, CANDIDATE, report)  # the forged live report
    _write(root, se.REPORTS[0], report)
    p = ms.model_role_problems(_swap(report), se.from_git(root, "HEAD"))
    assert any("does not resolve in the model store" in x for x in p), p
    assert any("is not supplied" in x for x in p), p


def test_the_store_must_be_on_the_base(tmp_path):
    root = tmp_path / "repo"
    _base_files(root, store=False)
    _git(root, "init", "-q")
    _commit(root)
    shutil.copy(STORE_FILE, root / se.STORE)
    _write(root, se.ROLES, _rebound_doc())
    with pytest.raises(se.EvidenceError, match=r"model_store\.json is not in .*the base's"):
        se.from_git(root, "HEAD")
    assert se.from_git(root, "HEAD", store=None).store is None


def test_the_suites_are_read_at_the_base(repo):
    """A suite edited in the working tree is not the one the report is checked with."""
    (repo / se.SUITES[0]).write_text("edited: true\n", encoding="utf-8")
    ev = se.from_git(repo, "HEAD")
    assert [p.read_bytes() for p in ev.suites] == [p.read_bytes() for p in gp.DEFAULT_SUITES]


def test_the_suites_directory_goes_with_the_evidence(repo):
    ev = se.from_git(repo, "HEAD")
    d = ev.suites[0].parent.parent
    assert d.is_dir()
    del ev
    import gc

    gc.collect()
    assert not d.exists()


def test_a_table_missing_at_the_base_is_refused(tmp_path):
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "x.md").write_text("x\n")
    _git(root, "init", "-q")
    _commit(root)
    _write(root, se.ROLES, _rebound_doc())
    with pytest.raises(se.EvidenceError, match=r"is not in .*: the evidence is the base's"):
        se.from_git(root, "HEAD", store=None)


@pytest.mark.parametrize(
    "base",
    ["no-such-ref", "HEAD~5", "-h", "--all", "--upload-pack=touch", "HEAD^{tree}", "HEAD:examples"],
)
def test_a_base_that_is_no_commit_is_refused(repo, base):
    with pytest.raises(se.EvidenceError, match="not a commit here"):
        se.from_git(repo, base)


def test_an_empty_base_is_refused(repo):
    for base in ("", " "):
        with pytest.raises(se.EvidenceError, match="needs a commit"):
            se.resolve_base(repo, base)


def test_the_base_is_resolved_to_a_commit_once(repo):
    sha = se.resolve_base(repo, "HEAD")
    assert len(sha) == 40 and sha == _git(repo, "rev-parse", "HEAD")


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


def test_a_linked_root_is_refused(repo, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(repo)
    with pytest.raises(se.EvidenceError, match="a symbolic link on its path"):
        se.read_head(link, se.ROLES)


def test_a_fifo_table_is_refused_without_blocking(repo):
    (repo / se.ROLES).unlink()
    os.mkfifo(repo / se.ROLES)
    with pytest.raises(se.EvidenceError, match="not a regular file"):
        se.from_git(repo, "HEAD")


@pytest.mark.parametrize("rel", [se.ROLES, se.STORE])
def test_a_symbolic_link_at_the_base_is_refused(tmp_path, rel):
    root = tmp_path / "repo"
    _base_files(root)
    _write(root, "real.json", json.loads((root / rel).read_text(encoding="utf-8")))
    (root / rel).unlink()
    (root / rel).symlink_to(os.path.relpath(root / "real.json", (root / rel).parent))
    _git(root, "init", "-q")
    _commit(root)
    with pytest.raises(se.EvidenceError, match=r"at [0-9a-f]{12}: a symbolic link"):
        se.read_base(root, "HEAD", rel)


@pytest.mark.parametrize("rel", [se.ROLES, se.STORE])
def test_an_oversized_file_at_the_base_is_refused(repo, monkeypatch, rel):
    monkeypatch.setattr(se.ld, "MAX_BYTES", 64)
    with pytest.raises(se.EvidenceError, match="over 64 bytes"):
        se.read_base(repo, "HEAD", rel)


def test_too_many_candidate_reports_are_refused(repo, monkeypatch, report):
    _write(repo, f"{se.EVALS}/second.json", report)
    _commit(repo)
    monkeypatch.setattr(se, "MAX_EVALS", 1)
    with pytest.raises(se.EvidenceError, match="over 1 reports"):
        se.from_git(repo, "HEAD")


def test_a_doctored_table_after_is_caught(repo, report):
    """The working tree claims other weights for the new binding than the report and the store
    evidence: the leg's pin no longer resolves, and the report is stale for the table."""
    _write(repo, se.ROLES, _rebound_doc(digest="sha256:" + "1" * 64))
    p = ms.model_role_problems(_swap(report), se.from_git(repo, "HEAD"))
    assert any("the new binding does not resolve in the role table after" in x for x in p)


def test_the_policy_not_the_record_decides_live(repo, report):
    swap = _swap(report)
    swap["model_roles"][0]["evaluation"]["require_live"] = False
    assert se.from_git(repo, "HEAD").require_live is True
    assert ms.model_role_problems(swap, se.from_git(repo, "HEAD")) == []


def test_an_extra_report_is_read_but_never_through_a_link(repo, report, tmp_path):
    extra = _write(tmp_path, "extra.json", report)
    ev = se.from_git(repo, "HEAD", extra_reports=[extra])
    assert len(ev.reports) == 2
    link = tmp_path / "link.json"
    link.symlink_to(extra)
    with pytest.raises(se.EvidenceError, match="a symbolic link"):
        se.from_git(repo, "HEAD", extra_reports=[link])


# ------------------------------------------------------------------------------- swap-check


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


def _cli(root: Path, record: Path, capsys, *extra: str, base=("--base", "HEAD")):
    rc = mcli.main(
        ["swap-check", str(record), "--root", str(root), "--examples", *base,
         "--site", str(root / "examples/modules/sites/full.yml"), "--json", *extra]
    )  # fmt: skip
    out = capsys.readouterr()
    return rc, (json.loads(out.out) if out.out else out.err)


def test_the_cli_checks_a_rebind_end_to_end(checkout, report, capsys, tmp_path):
    record = _write(tmp_path, "swap.json", _swap(report))
    rc, out = _cli(checkout, record, capsys)
    assert (rc, out["problems"], out["evidence"]) == (0, [], True)


def test_the_cli_takes_the_ci_base(checkout, report, capsys, tmp_path, monkeypatch):
    base = _git(checkout, "rev-parse", "HEAD")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("HNX_PR_BASE", base)
    record = _write(tmp_path, "swap.json", _swap(report))
    rc, out = _cli(checkout, record, capsys, base=("--ci-base",))
    assert (rc, out["problems"], out["base"]) == (0, [], base)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    rc, err = _cli(checkout, record, capsys, base=("--ci-base",))
    assert rc == 2 and "only push and pull_request have a base rule" in err


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


def test_the_cli_refuses_an_overlay(checkout, report, capsys, tmp_path):
    record = _write(tmp_path, "swap.json", _swap(report))
    rc, err = _cli(checkout, record, capsys, "--overlay", str(tmp_path))
    assert rc == 2 and "--overlay: swap-check reads" in err


def test_the_cli_refuses_an_option_as_the_base(checkout, report, capsys, tmp_path):
    record = _write(tmp_path, "swap.json", _swap(report))
    rc, err = _cli(checkout, record, capsys, base=("--base=--upload-pack=touch",))
    assert rc == 2 and "not a commit here" in err


@pytest.mark.parametrize("fault", [subprocess.TimeoutExpired("git", 60), FileNotFoundError("git")])
def test_git_that_cannot_run_is_could_not_check(checkout, report, capsys, tmp_path, monkeypatch,
                                                fault):  # fmt: skip
    def run(*args, **kwargs):
        raise fault

    monkeypatch.setattr(se.subprocess, "run", run)
    rc, err = _cli(checkout, _write(tmp_path, "swap.json", _swap(report)), capsys)
    assert rc == 100 and "internal error" in err


# ------------------------------------------------------------------------------- swap-gate


def _gate(root: Path, capsys, base: str = "HEAD") -> tuple[int, dict]:
    rc = mcli.main(["swap-gate", "--root", str(root), "--base", base, "--json"])
    return rc, json.loads(capsys.readouterr().out)


def test_an_unchanged_role_table_passes_the_gate(repo, capsys):
    _write(repo, se.ROLES, json.loads(ROLES.read_text(encoding="utf-8")))
    rc, out = _gate(repo, capsys)
    assert (rc, out["problems"]) == (0, []) and "unchanged" in out["decided"]


def test_an_uncovered_role_table_change_fails_the_gate(repo, capsys):
    rc, out = _gate(repo, capsys)
    assert rc == 1
    (p,) = out["problems"]
    assert "roles: fast-classifier" in p and f"no swap record under {se.SWAPS}/" in p


def test_a_record_in_the_change_covers_it(repo, report, capsys):
    _write(repo, f"{se.SWAPS}/fast-classifier.json", _swap(report))
    rc, out = _gate(repo, capsys)
    assert (rc, out["problems"]) == (0, []), out


def test_a_record_that_does_not_hold_fails_the_gate(repo, report, capsys):
    swap = _swap(report)
    swap["model_roles"][0]["evaluation"]["report"] = "sha256:" + "2" * 64
    _write(repo, f"{se.SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(repo, capsys)
    assert rc == 1 and any("is not supplied" in p for p in out["problems"])


def test_a_record_the_schema_refuses_fails_the_gate(repo, report, capsys):
    swap = _swap(report)
    del swap["route"]
    _write(repo, f"{se.SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(repo, capsys)
    assert rc == 1 and all(": record: " in p for p in out["problems"])


def test_a_record_already_on_the_base_covers_nothing(repo, report, capsys):
    """Only a record the change adds or edits counts: one committed earlier covered that change."""
    _write(repo, se.ROLES, json.loads(ROLES.read_text(encoding="utf-8")))
    _write(repo, f"{se.SWAPS}/fast-classifier.json", _swap(report))
    _commit(repo)
    _write(repo, se.ROLES, _rebound_doc())
    assert se.changed_records(repo, "HEAD") == []
    assert _gate(repo, capsys)[0] == 1


def test_a_linked_record_fails_the_gate(repo, report, capsys, tmp_path):
    (repo / se.SWAPS).mkdir(parents=True)
    (repo / se.SWAPS / "x.json").symlink_to(_write(tmp_path, "x.json", _swap(report)))
    rc, out = _gate(repo, capsys)
    assert rc == 1 and any("a symbolic link on its path" in p for p in out["problems"])


# ------------------------------------------------- S4: the gate ties a record to what changed


def _trust_repo(repo: Path, *, flag_on: str) -> Path:
    """The base marks ``flag_on``'s first binding ``leaves_lab``; the working tree is the
    shipped table (rebinding nothing)."""
    base = json.loads(ROLES.read_text(encoding="utf-8"))
    base["roles"][flag_on]["bindings"][0]["leaves_lab"] = True
    _write(repo, se.ROLES, base)
    _commit(repo)
    _write(repo, se.ROLES, json.loads(ROLES.read_text(encoding="utf-8")))
    return repo


def test_a_dropped_leaves_lab_is_a_role_change(repo, capsys):
    """S4: ``leaves_lab`` is in no pin, so the gate saw no changed role."""
    _trust_repo(repo, flag_on="main-reasoner")
    rc, out = _gate(repo, capsys)
    assert rc == 1
    assert any("mdl:main-reasoner" in p and "leaves_lab" in p for p in out["problems"]), out


def test_an_unrelated_record_does_not_cover_a_trust_change(repo, report, capsys):
    """S4: a record that rebinds another role (or none) covered any change to the table."""
    _trust_repo(repo, flag_on="main-reasoner")
    swap = _swap(report)
    del swap["model_roles"]
    _write(repo, f"{se.SWAPS}/unrelated.json", swap)
    rc, out = _gate(repo, capsys)
    assert rc == 1 and any("mdl:main-reasoner" in p for p in out["problems"]), out


def test_a_record_naming_the_role_covers_a_trust_change(repo, report, capsys):
    _trust_repo(repo, flag_on="main-reasoner")
    swap = _swap(report)
    del swap["model_roles"]
    swap["model_role_changes"] = ["mdl:main-reasoner"]
    _write(repo, f"{se.SWAPS}/trust.json", swap)
    rc, out = _gate(repo, capsys)
    assert (rc, out["problems"]) == (0, []), out


def test_a_record_naming_a_role_that_did_not_change_is_refused(repo, report, capsys):
    _trust_repo(repo, flag_on="main-reasoner")
    swap = _swap(report)
    del swap["model_roles"]
    swap["model_role_changes"] = ["mdl:main-reasoner", "mdl:fast-classifier"]
    _write(repo, f"{se.SWAPS}/trust.json", swap)
    rc, out = _gate(repo, capsys)
    assert rc == 1 and any(
        "mdl:fast-classifier" in p and "did not change" in p for p in out["problems"]
    ), out


def test_a_rebind_record_does_not_cover_another_roles_trust_change(repo, report, capsys):
    """The rebind of fast-classifier is covered by its leg; a leaves_lab dropped on
    main-reasoner in the same change is not."""
    base = json.loads(ROLES.read_text(encoding="utf-8"))
    base["roles"]["main-reasoner"]["bindings"][0]["leaves_lab"] = True
    _write(repo, se.ROLES, base)
    _write(repo, CANDIDATE, report)
    _commit(repo)
    _write(repo, se.ROLES, _rebound_doc())  # fast-classifier rebound, main-reasoner flag dropped
    _write(repo, f"{se.SWAPS}/fast-classifier.json", _swap(report))
    rc, out = _gate(repo, capsys)
    assert rc == 1
    assert any("mdl:main-reasoner" in p for p in out["problems"]), out
    assert not any("mdl:fast-classifier" in p for p in out["problems"]), out


def _pair(first: dict, second: dict) -> dict:
    """The shipped table with ``mdl:main-reasoner`` bound to two bindings (pins only: a digest
    each), ``first`` and ``second`` the keys each carries beside its pin."""
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    pin = doc["roles"]["main-reasoner"]["bindings"][0]
    doc["roles"]["main-reasoner"]["bindings"] = [
        {**pin, "digest": "sha256:" + "a" * 64, **first},
        {**pin, "digest": "sha256:" + "b" * 64, **second},
    ]
    return doc


def _trust_pair(repo: Path, base: dict, head: dict) -> None:
    _write(repo, se.ROLES, base)
    _commit(repo)
    _write(repo, se.ROLES, head)


def test_a_leaves_lab_moved_to_another_binding_is_a_change(repo, capsys):
    """The flag moved from the second binding to the first: the multiset of non-pin keys was the
    same, so the gate saw nothing; keyed by each binding's pin it is a change."""
    _trust_pair(repo, _pair({}, {"leaves_lab": True}), _pair({"leaves_lab": True}, {}))
    rc, out = _gate(repo, capsys)
    assert rc == 1
    assert any("mdl:main-reasoner" in p and "bindings[].leaves_lab" in p for p in out["problems"])


def test_the_same_flag_on_the_same_binding_is_no_change(repo, capsys):
    both = _pair({}, {"leaves_lab": True})
    _trust_pair(repo, both, both | {"x": 1})
    assert se._trust_changes(both, both) == {}
    assert se._trust_changes(both, _pair({}, {"leaves_lab": True})) == {}


def test_moved_bindings_keep_their_flag_with_their_pin():
    """Reordering the bindings is not a change when each flag stays with its pin."""
    a, b = _pair({"leaves_lab": True}, {}), _pair({"leaves_lab": True}, {})
    b["roles"]["main-reasoner"]["bindings"].reverse()
    assert se._trust_changes(a, b) == {}


@pytest.mark.parametrize("value", [False, None, "true", 1, 0])
def test_a_leaves_lab_the_rules_do_not_read_as_true_equals_the_key_absent(value, repo, capsys):
    """``rules.cloud_roles`` tests ``is True``: ``false`` (or any other value) reads as absent, so
    swapping one for the other is no change and needs no record."""
    base = json.loads(ROLES.read_text(encoding="utf-8"))
    head = json.loads(ROLES.read_text(encoding="utf-8"))
    head["roles"]["main-reasoner"]["bindings"][0]["leaves_lab"] = value
    assert se._trust_changes(base, head) == {} == se._trust_changes(head, base)
    _write(repo, se.ROLES, base)
    _commit(repo)
    _write(repo, se.ROLES, head)
    rc, out = _gate(repo, capsys)
    assert (rc, out["problems"]) == (0, []) and "reads the same" in out["decided"]


def test_true_against_false_is_still_a_change(repo, capsys):
    base = json.loads(ROLES.read_text(encoding="utf-8"))
    base["roles"]["main-reasoner"]["bindings"][0]["leaves_lab"] = False
    head = json.loads(ROLES.read_text(encoding="utf-8"))
    head["roles"]["main-reasoner"]["bindings"][0]["leaves_lab"] = True
    _trust_pair(repo, base, head)
    rc, out = _gate(repo, capsys)
    assert rc == 1 and any("bindings[].leaves_lab" in p for p in out["problems"])


# ------------------------------------------- the gate over a private overlay's lab/ layout

LAB_ROLES = "lab/model_roles.json"
LAB_STORE = "lab/model-serving/model_store.json"
LAB_EVALS = "lab/model-evals"
LAB_SWAPS = "lab/swaps"


@pytest.fixture
def overlay(tmp_path, report) -> Path:
    """An overlay checkout: the base commit holds the role table, the store and the live report
    under ``lab/`` (no golden suites: those are the installed hnx's); the working tree rebinds
    ``mdl:fast-classifier``."""
    root = tmp_path / "overlay"
    (root / "lab" / "model-serving").mkdir(parents=True)
    shutil.copy(ROLES, root / LAB_ROLES)
    shutil.copy(STORE_FILE, root / LAB_STORE)
    _write(root, f"{LAB_EVALS}/fast-classifier.json", report)
    _git(root, "init", "-q")
    _commit(root)
    _write(root, LAB_ROLES, _rebound_doc())
    return root


def _ogate(root: Path, capsys, *extra: str, base: str = "HEAD") -> tuple[int, dict]:
    rc = mcli.main(["swap-gate", "--overlay", str(root), "--base", base, "--json", *extra])
    return rc, json.loads(capsys.readouterr().out)


def test_an_overlay_change_covered_by_a_lab_record_passes(overlay, report, capsys):
    _write(overlay, f"{LAB_SWAPS}/fast-classifier.json", _swap(report))
    rc, out = _ogate(overlay, capsys)
    assert (rc, out["problems"]) == (0, []), out


def test_the_same_overlay_change_uncovered_fails(overlay, capsys):
    rc, out = _ogate(overlay, capsys)
    assert rc == 1
    (p,) = out["problems"]
    assert f"{LAB_ROLES} changes" in p and f"no swap record under {LAB_SWAPS}/" in p
    assert LAB_STORE in p and LAB_EVALS in p


def test_a_record_under_the_repositorys_paths_covers_nothing_in_an_overlay(overlay, report, capsys):
    _write(overlay, f"{se.SWAPS}/fast-classifier.json", _swap(report))
    assert _ogate(overlay, capsys)[0] == 1


def test_the_overlay_evidence_is_the_bases_not_the_changes(tmp_path, report, capsys):
    """A store entry and a live report committed in the same change as the rebind vouch for
    nothing: the base has neither."""
    root = tmp_path / "overlay"
    (root / "lab" / "model-serving").mkdir(parents=True)
    shutil.copy(ROLES, root / LAB_ROLES)
    _git(root, "init", "-q")
    _commit(root)
    _write(root, LAB_ROLES, _rebound_doc())
    shutil.copy(STORE_FILE, root / LAB_STORE)
    _write(root, f"{LAB_EVALS}/fast-classifier.json", report)
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _swap(report))
    rc = mcli.main(["swap-gate", "--overlay", str(root), "--base", "HEAD", "--json"])
    err = capsys.readouterr().err
    assert rc == 2 and f"{LAB_STORE} is not in" in err


def test_an_overlay_report_added_in_the_change_does_not_hold_the_record(overlay, report, capsys):
    other = {**report, "model": "someone-else"}
    swap = _swap(other)  # pins a digest only the change's own (untracked) report would give
    _write(overlay, f"{LAB_EVALS}/new.json", other)
    _write(overlay, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _ogate(overlay, capsys)
    assert rc == 1 and any("is not supplied" in p for p in out["problems"])


def test_the_overlay_head_table_is_not_read_through_a_link(overlay, tmp_path, capsys):
    (overlay / LAB_ROLES).unlink()
    (overlay / LAB_ROLES).symlink_to(_write(tmp_path, "t.json", _rebound_doc()))
    rc = mcli.main(["swap-gate", "--overlay", str(overlay), "--base", "HEAD", "--json"])
    assert rc == 2 and "a symbolic link" in capsys.readouterr().err


def test_a_linked_lab_directory_in_the_overlay_is_refused(overlay, report, tmp_path):
    real = tmp_path / "elsewhere"
    _write(real, "fast-classifier.json", _swap(report))
    (overlay / LAB_SWAPS).symlink_to(real)
    rc = mcli.main(["swap-gate", "--overlay", str(overlay), "--base", "HEAD", "--json"])
    assert rc == 1


def test_an_overlay_without_a_role_table_at_the_base_is_refused(tmp_path, capsys):
    root = tmp_path / "overlay"
    root.mkdir()
    (root / "README").write_text("x")
    _git(root, "init", "-q")
    _commit(root)
    _write(root, LAB_ROLES, _rebound_doc())
    rc = mcli.main(["swap-gate", "--overlay", str(root), "--base", "HEAD"])
    assert rc == 2 and f"{LAB_ROLES} is not in" in capsys.readouterr().err


def test_an_unchanged_overlay_table_passes(overlay, capsys):
    _write(overlay, LAB_ROLES, json.loads(ROLES.read_text(encoding="utf-8")))
    rc, out = _ogate(overlay, capsys)
    assert (rc, out["problems"]) == (0, []) and "unchanged" in out["decided"]


def test_the_overlay_takes_the_ci_base(overlay, report, capsys, monkeypatch):
    _write(overlay, f"{LAB_SWAPS}/fast-classifier.json", _swap(report))
    sha = _git(overlay, "rev-parse", "HEAD")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("HNX_PR_BASE", sha)
    rc = mcli.main(["swap-gate", "--overlay", str(overlay), "--ci-base", "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["problems"] == []


@pytest.mark.parametrize("extra", [["--root"], ["--roles", "x.json"]])
def test_overlay_refuses_root_and_roles(overlay, extra, tmp_path, capsys):
    args = ["swap-gate", "--overlay", str(overlay), "--base", "HEAD", *extra]
    if extra[0] == "--root":
        args.append(str(tmp_path))
    assert mcli.main(args) == 2 and "--overlay" in capsys.readouterr().err


def test_overlay_must_be_a_directory(tmp_path, capsys):
    rc = mcli.main(["swap-gate", "--overlay", str(tmp_path / "nope"), "--base", "HEAD"])
    assert rc == 2 and "not a directory" in capsys.readouterr().err


def test_repository_mode_paths_are_unchanged():
    assert (se.ROLES, se.STORE, se.REPORTS, se.EVALS, se.SWAPS) == (
        "examples/model_roles.json",
        "examples/model-serving/model_store.json",
        ("examples/model_roles.eval.json",),
        "examples/model-evals",
        "examples/swaps",
    )
    repo = se.Layout(se.ROLES, se.STORE, se.REPORTS, se.EVALS, se.SWAPS, se.SUITES)
    assert repo == se.REPO
    assert se.OVERLAY.suites is None  # the installed hnx's golden suites


@pytest.mark.parametrize("field", ["leaves_lab", "fallback"])
def test_an_overlay_trust_change_needs_a_record_naming_the_role(overlay, report, capsys, field):
    base = json.loads(ROLES.read_text(encoding="utf-8"))
    head = json.loads(ROLES.read_text(encoding="utf-8"))
    if field == "leaves_lab":
        head["roles"]["main-reasoner"]["bindings"][0]["leaves_lab"] = True
    else:
        del head["roles"]["main-reasoner"]["fallback"]
    _write(overlay, LAB_ROLES, base)
    _commit(overlay)
    _write(overlay, LAB_ROLES, head)
    assert _ogate(overlay, capsys)[0] == 1  # no record at all
    swap = _swap(report)
    del swap["model_roles"]
    _write(overlay, f"{LAB_SWAPS}/other.json", swap)  # a record, naming no role
    rc, out = _ogate(overlay, capsys)
    assert rc == 1 and any(
        "mdl:main-reasoner" in p and field in p and "model_role_changes" in p
        for p in out["problems"]
    ), out
    swap["model_role_changes"] = ["mdl:main-reasoner"]
    _write(overlay, f"{LAB_SWAPS}/other.json", swap)
    rc, out = _ogate(overlay, capsys)
    assert (rc, out["problems"]) == (0, []), out


def test_the_overlay_takes_a_push_events_base(overlay, report, capsys, monkeypatch):
    _write(overlay, f"{LAB_SWAPS}/fast-classifier.json", _swap(report))
    sha = _git(overlay, "rev-parse", "HEAD")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("HNX_PUSH_BEFORE", sha)
    monkeypatch.delenv("HNX_PR_BASE", raising=False)
    rc = mcli.main(["swap-gate", "--overlay", str(overlay), "--ci-base", "--json"])
    cap = capsys.readouterr()
    assert rc == 0 and json.loads(cap.out)["problems"] == []
    assert f"base {sha}" in cap.err
    (overlay / LAB_SWAPS / "fast-classifier.json").unlink()  # uncovered against that push base
    rc = mcli.main(["swap-gate", "--overlay", str(overlay), "--ci-base", "--json"])
    assert rc == 1


def test_an_overlay_that_is_not_the_git_root_is_refused(overlay, tmp_path, capsys):
    sub = overlay / "sub"
    sub.mkdir()
    rc = mcli.main(["swap-gate", "--overlay", str(sub), "--base", "HEAD"])
    err = capsys.readouterr().err
    assert rc == 2 and "not the root of a git checkout" in err and str(overlay.resolve()) in err
    bare = tmp_path / "plain"
    bare.mkdir()
    rc = mcli.main(["swap-gate", "--overlay", str(bare), "--base", "HEAD"])
    assert rc == 2 and "not the root of a git checkout" in capsys.readouterr().err


def test_an_overlay_given_through_a_link_to_its_root_is_accepted(overlay, tmp_path, capsys):
    link = tmp_path / "link"
    link.symlink_to(overlay, target_is_directory=True)
    rc = mcli.main(["swap-gate", "--overlay", str(link), "--base", "HEAD", "--json"])
    assert rc == 1 and json.loads(capsys.readouterr().out)["decided"] == "uncovered"
