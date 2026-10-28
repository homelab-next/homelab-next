# SPDX-License-Identifier: Apache-2.0
"""hnx site review-tier: trust-widening site and selection fields are human-approve, against a
base read through git (docs/private-overlay.md, "What a change to the lab claims")."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext import paths
from homelabnext.modules import loader as ld
from homelabnext.modules import swap_evidence as se
from homelabnext.network import cli as ncli
from homelabnext.network import review_tier as rt

SITE = yaml.safe_load((paths.example_file("minimal", "site.yml")).read_text())
OWNERS = "/lab/site.yml @lab-owner-fake\n/lab/modules.yml @lab-owner-fake\n"
SCOPE = {
    "trusted": {"nets": ["192.0.2.0/24"]},
    "target": ["192.0.2.0/26"],
    "exclude": {"unattended_mutation": ["192.0.2.1"], "offensive": []},
}


def tiers(changes) -> dict[str, str]:
    out: dict[str, str] = {}
    for c in changes:
        # human wins when one field changes both ways
        if out.get(c.field) != rt.HUMAN:
            out[c.field] = c.tier
    return out


def _site(**edits) -> dict:
    doc = copy.deepcopy(SITE)
    doc.update(edits)
    return doc


# ---- the site's fields ---------------------------------------------------------------------


def test_an_unchanged_site_or_a_reordered_list_is_no_change():
    assert rt.site_changes(SITE, copy.deepcopy(SITE)) == []
    doc = copy.deepcopy(SITE)
    doc["firewall"]["zone_to_zone"].reverse()
    assert rt.site_changes(SITE, doc) == []


def test_a_delegated_prefix_added_is_human_and_removed_is_owner():
    entry = {"prefix": "2001:db8:5::/48", "why": "the ISP's delegation"}
    added = rt.site_changes(SITE, _site(delegated_prefixes6=[entry]))
    assert tiers(added) == {"delegated_prefixes6.2001:db8:5::/48": rt.HUMAN}
    removed = rt.site_changes(_site(delegated_prefixes6=[entry]), SITE)
    assert tiers(removed) == {"delegated_prefixes6.2001:db8:5::/48": rt.OWNER}
    # a changed why is a removal and an addition: the new entry is human-approve
    changed = rt.site_changes(
        _site(delegated_prefixes6=[entry]),
        _site(delegated_prefixes6=[{**entry, "why": "another reason"}]),
    )
    assert tiers(changed)["delegated_prefixes6.2001:db8:5::/48"] == rt.HUMAN


def test_a_new_zone_and_a_changed_range_are_human_a_removed_one_owner():
    doc = copy.deepcopy(SITE)
    doc["zones"].append({**doc["zones"][0], "id": "extra", "vlan_id": 60})
    assert tiers(rt.site_changes(SITE, doc)) == {"zones.extra": rt.HUMAN}
    assert tiers(rt.site_changes(doc, SITE)) == {"zones.extra": rt.OWNER}
    doc = copy.deepcopy(SITE)
    doc["zones"][1]["subnet"] = "192.0.2.64/25"
    assert tiers(rt.site_changes(SITE, doc)) == {"zones.data.subnet": rt.HUMAN}
    doc = copy.deepcopy(SITE)
    doc["zones"][1]["subnet6"] = "2001:db8:0:20::/64"  # added where there was none
    assert tiers(rt.site_changes(SITE, doc)) == {"zones.data.subnet6": rt.HUMAN}
    assert tiers(rt.site_changes(doc, SITE)) == {"zones.data.subnet6": rt.OWNER}


def test_egress_opened_is_human_and_closed_is_owner():
    doc = copy.deepcopy(SITE)
    doc["zones"][0]["egress"]["internet"] = "allow"  # mgmt: deny to allow
    assert tiers(rt.site_changes(SITE, doc)) == {"zones.mgmt.egress": rt.HUMAN}
    assert tiers(rt.site_changes(doc, SITE)) == {"zones.mgmt.egress": rt.OWNER}
    doc = copy.deepcopy(SITE)
    del doc["zones"][4]["egress"]["one_way"]  # sandbox: one_way off
    assert tiers(rt.site_changes(SITE, doc)) == {"zones.sandbox.egress": rt.HUMAN}


def test_an_allow_added_or_a_deny_removed_is_human_the_reverse_owner():
    allow = {"from": "edge", "to": "compute", "action": "allow", "ports": [443]}
    doc = copy.deepcopy(SITE)
    doc["firewall"]["zone_to_zone"].append(allow)
    assert tiers(rt.site_changes(SITE, doc)) == {"firewall.zone_to_zone": rt.HUMAN}
    assert tiers(rt.site_changes(doc, SITE)) == {"firewall.zone_to_zone": rt.OWNER}
    doc = copy.deepcopy(SITE)
    doc["firewall"]["zone_to_zone"] = [
        r for r in doc["firewall"]["zone_to_zone"] if r["action"] != "deny"
    ]
    assert tiers(rt.site_changes(SITE, doc)) == {"firewall.zone_to_zone": rt.HUMAN}
    doc = copy.deepcopy(SITE)
    doc["firewall"]["service_exceptions"].append(
        {"from": "zone:edge", "to": "svc:events", "action": "allow"}
    )
    assert tiers(rt.site_changes(SITE, doc)) == {"firewall.service_exceptions": rt.HUMAN}
    # an allow whose ports widen is a removal and an addition: human
    doc = copy.deepcopy(SITE)
    doc["firewall"]["zone_to_zone"][1]["ports"] = [22, 443, 8443]
    assert tiers(rt.site_changes(SITE, doc))["firewall.zone_to_zone"] == rt.HUMAN


def test_tailnet_is_human_and_a_field_that_widens_nothing_is_owner():
    doc = copy.deepcopy(SITE)
    doc["tailnet"]["deploy"]["zones"] = ["mgmt", "data", "compute"]
    assert tiers(rt.site_changes(SITE, doc)) == {"tailnet": rt.HUMAN}
    doc = copy.deepcopy(SITE)
    doc["dns"]["policy"]["ttl_default"] = 600
    doc["zones"][0]["vlan_id"] = 11
    assert tiers(rt.site_changes(SITE, doc)) == {"dns": rt.OWNER, "zones.mgmt": rt.OWNER}


def test_a_shape_that_cannot_be_compared_is_human():
    assert tiers(rt.site_changes(SITE, _site(zones={"mgmt": {}})))["zones"] == rt.HUMAN
    dup = _site(zones=[SITE["zones"][0], SITE["zones"][0]])
    assert tiers(rt.site_changes(SITE, dup))["zones"] == rt.HUMAN
    assert (
        tiers(rt.site_changes(SITE, _site(delegated_prefixes6="2001:db8::/48")))[
            "delegated_prefixes6"
        ]
        == rt.HUMAN
    )
    assert tiers(rt.site_changes(SITE, ["not", "a", "site"]))["site"] == rt.HUMAN
    doc = copy.deepcopy(SITE)
    doc["firewall"]["default_action"] = "allow"
    assert tiers(rt.site_changes(SITE, doc))["firewall"] == rt.HUMAN


# ---- the selection's scope and grants -------------------------------------------------------


def _sel(scope=None, grants=None) -> dict:
    doc: dict = {"profile": "small-lab"}
    if scope is not None:
        doc["scope"] = scope
    if grants is not None:
        doc["grants"] = grants
    return doc


def test_trusted_and_target_added_are_human_removed_owner():
    wider = copy.deepcopy(SCOPE)
    wider["trusted"]["nets"].append("198.51.100.0/24")
    wider["target"].append("198.51.100.0/26")
    wider["trusted"]["tooling"] = ["192.0.2.10"]
    t = tiers(rt.scope_changes(_sel(SCOPE), _sel(wider)))
    assert t == {
        "scope.trusted.nets": rt.HUMAN,
        "scope.trusted.tooling": rt.HUMAN,
        "scope.target": rt.HUMAN,
    }
    assert set(tiers(rt.scope_changes(_sel(wider), _sel(SCOPE))).values()) == {rt.OWNER}


def test_an_exclusion_removed_or_declared_where_absent_is_human():
    fewer = copy.deepcopy(SCOPE)
    fewer["exclude"]["unattended_mutation"] = []
    assert tiers(rt.scope_changes(_sel(SCOPE), _sel(fewer))) == {
        "scope.exclude.unattended_mutation": rt.HUMAN
    }
    assert tiers(rt.scope_changes(_sel(fewer), _sel(SCOPE))) == {
        "scope.exclude.unattended_mutation": rt.OWNER
    }
    absent = copy.deepcopy(SCOPE)
    del absent["exclude"]["offensive"]
    # absent fails closed in every reader; [] excludes nothing
    assert tiers(rt.scope_changes(_sel(absent), _sel(SCOPE))) == {
        "scope.exclude.offensive": rt.HUMAN
    }
    assert tiers(rt.scope_changes(_sel(SCOPE), _sel(absent))) == {
        "scope.exclude.offensive": rt.OWNER
    }


def test_an_unknown_scope_part_is_human():
    odd = copy.deepcopy(SCOPE)
    odd["trusted"]["other"] = ["192.0.2.0/24"]
    assert tiers(rt.scope_changes(_sel(SCOPE), _sel(odd)))["scope.trusted.other"] == rt.HUMAN
    odd = {**copy.deepcopy(SCOPE), "extra": True}
    assert tiers(rt.scope_changes(_sel(SCOPE), _sel(odd)))["scope"] == rt.HUMAN


def test_a_grant_added_is_human_and_removed_owner():
    before = {"egress": {"collector": {"edge": ["internet"]}}}
    after = {"egress": {"collector": {"edge": ["internet"], "core": ["svc:events"]}}}
    assert tiers(rt.scope_changes(_sel(grants=before), _sel(grants=after))) == {
        "grants.egress.collector.core": rt.HUMAN
    }
    assert tiers(rt.scope_changes(_sel(grants=after), _sel(grants=before))) == {"grants": rt.OWNER}
    # the rest of a selection is the loader's
    assert rt.scope_changes({"profile": "a"}, {"profile": "b"}) == []


# ---- the review, against a base read through git ---------------------------------------------


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


def _write(root: Path, rel: str, doc) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(doc if isinstance(doc, str) else yaml.safe_dump(doc), encoding="utf-8")


@pytest.fixture
def lab(tmp_path: Path) -> tuple[Path, str]:
    """An overlay-shaped repository: the example site at lab/site.yml, a selection with a
    scope, CODEOWNERS naming both, committed; returns (root, the base commit)."""
    root = tmp_path / "lab"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, rt.SITE, SITE)
    _write(root, rt.SELECTION, _sel(SCOPE))
    _write(root, ".github/CODEOWNERS", OWNERS)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root, _git(root, "rev-parse", "HEAD")


def _widen(root: Path) -> None:
    entry = {"prefix": "2001:db8:5::/48", "why": "the ISP's delegation"}
    _write(root, rt.SITE, _site(delegated_prefixes6=[entry]))


def test_no_change_is_no_result(lab):
    root, base = lab
    assert rt.review(root, base) == ([], [])


def test_a_human_change_with_a_base_owner_is_no_problem(lab):
    root, base = lab
    _widen(root)
    results, problems = rt.review(root, base)
    assert problems == []
    (r,) = results
    assert (r.path, r.tier, r.owners) == (rt.SITE, rt.HUMAN, ["@lab-owner-fake"])


def test_owners_are_the_bases_not_the_changes(lab):
    root, base = lab
    _write(root, ".github/CODEOWNERS", "/README.md @lab-owner-fake\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "no owner for the site")
    base = _git(root, "rev-parse", "HEAD")
    _widen(root)
    _write(root, ".github/CODEOWNERS", OWNERS)  # the change cannot give itself an owner
    results, problems = rt.review(root, base)
    assert results[0].tier == rt.HUMAN and results[0].owners == []
    assert len(problems) == 1 and "no valid CODEOWNERS owner" in problems[0]


def test_an_owner_change_alone_raises_no_problem_without_an_owner(lab):
    root, base = lab
    doc = _site()
    doc["dns"]["policy"]["ttl_default"] = 600
    _write(root, rt.SITE, doc)
    _write(root, ".github/CODEOWNERS", "")
    (r,), problems = rt.review(root, base)
    assert r.tier == rt.OWNER and problems == []


def test_a_new_or_removed_file_is_human(lab):
    root, base = lab
    (root / rt.SELECTION).unlink()
    (r,), _ = rt.review(root, base)
    assert (r.path, r.tier) == (rt.SELECTION, rt.HUMAN)
    assert "removed" in r.changes[0].why
    _write(root, rt.SELECTION, _sel(SCOPE))
    _git(root, "rm", "-q", "--cached", rt.SELECTION)
    _git(root, "commit", "-qm", "no selection")
    base = _git(root, "rev-parse", "HEAD")
    (r,), _ = rt.review(root, base)
    assert r.tier == rt.HUMAN and "new in this change" in r.changes[0].why


def test_a_link_or_an_oversized_file_at_the_head_is_human(lab, tmp_path):
    root, base = lab
    (root / rt.SITE).unlink()
    (root / rt.SITE).symlink_to(tmp_path / "elsewhere.yml")
    (r,), _ = rt.review(root, base)
    assert r.tier == rt.HUMAN and "fail closed" in r.changes[0].why
    (root / rt.SITE).unlink()
    _write(root, rt.SITE, "#" * (ld.MAX_BYTES + 1))
    (r,), _ = rt.review(root, base)
    assert r.tier == rt.HUMAN and "fail closed" in r.changes[0].why


def test_a_link_or_an_unreadable_file_at_the_base_is_human(lab, tmp_path):
    root, _ = lab
    (root / rt.SITE).unlink()
    (root / rt.SITE).symlink_to("elsewhere.yml")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "a linked site")
    base = _git(root, "rev-parse", "HEAD")
    (root / rt.SITE).unlink()
    _write(root, rt.SITE, SITE)
    (r,), _ = rt.review(root, base)
    assert r.tier == rt.HUMAN and "symbolic link" in r.changes[0].why
    _write(root, rt.SITE, "zones: [\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "not YAML")
    base = _git(root, "rev-parse", "HEAD")
    _write(root, rt.SITE, SITE)
    (r,), _ = rt.review(root, base)
    assert r.tier == rt.HUMAN and "fail closed" in r.changes[0].why


def test_a_base_that_is_not_a_commit_is_refused(lab):
    root, _ = lab
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    for bad in ("--all", "-h", "", tree, "no-such-ref"):
        with pytest.raises(se.EvidenceError):
            rt.review(root, bad)


def test_a_root_commit_has_every_file_new(lab):
    root, _ = lab
    results, problems = rt.review(root, None)
    assert {r.path for r in results} == {rt.SITE, rt.SELECTION}
    assert all(r.tier == rt.HUMAN for r in results)
    assert problems  # no base, so no CODEOWNERS as of the base


# ---- the CLI --------------------------------------------------------------------------------


def _run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = ncli.main(["review-tier", *argv], out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_the_cli_reports_and_exits_by_problem(lab):
    root, base = lab
    assert _run("--root", str(root), "--base", base)[0] == 0
    _widen(root)
    code, out, _ = _run("--root", str(root), "--base", base)
    assert code == 0 and "human-approve: delegated_prefixes6.2001:db8:5::/48" in out
    code, out, _ = _run("--root", str(root), "--base", base, "--json")
    body = json.loads(out)
    assert code == 0 and body["files"][0]["tier"] == rt.HUMAN and body["problems"] == []
    _write(root, ".github/CODEOWNERS", "")
    _git(root, "add", ".github/CODEOWNERS")
    _git(root, "commit", "-qm", "no owners")
    base2 = _git(root, "rev-parse", "HEAD")
    assert _run("--root", str(root), "--base", base2)[0] == ncli.EXIT_INVALID
    assert _run("--root", str(root), "--base", "--all")[0] == ncli.EXIT_USAGE


def test_the_cli_takes_the_ci_base(lab, monkeypatch):
    root, base = lab
    _widen(root)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("HNX_PR_BASE", base)
    code, out, err = _run("--root", str(root), "--ci-base")
    assert code == 0 and "the pull request's base" in err and "human-approve" in out
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    assert _run("--root", str(root), "--ci-base")[0] == ncli.EXIT_USAGE


def test_the_cli_writes_the_step_summary(lab, monkeypatch, tmp_path):
    root, base = lab
    _widen(root)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert _run("--root", str(root), "--base", base)[0] == 0
    assert "| `lab/site.yml` | human-approve |" in summary.read_text()


def test_the_cli_takes_other_paths(lab):
    root, base = lab
    _write(root, "examples/site.yml", SITE)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "an example site")
    base = _git(root, "rev-parse", "HEAD")
    doc = _site()
    doc["tailnet"]["deploy"]["zones"] = ["mgmt"]
    _write(root, "examples/site.yml", doc)
    code, out, _ = _run("--root", str(root), "--base", base, "--site", "examples/site.yml")
    assert code == 1 and "human-approve: tailnet" in out  # no owner for that path
