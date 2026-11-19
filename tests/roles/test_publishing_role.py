# SPDX-License-Identifier: Apache-2.0
"""Role ``publishing_gate`` (modules/publishing/roles/publishing_gate), run on localhost against
fakes (CI is unprivileged): the pin is enforced by the role (an exact version, a lockfile pinned by
sha256), mode and TLP combinations that cannot be honoured are refused, credentials are written by
name as 0600 files and only the ones the mode needs, and the configuration holds no secret."""

from __future__ import annotations

import json
import os
import pwd
from pathlib import Path

import pytest
from rolerun import run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "publishing" / "roles" / "publishing_gate")
USER = pwd.getpwuid(os.getuid()).pw_name
SECRET_VALUE = "dv" * 3
LOCK_PIN = (
    "a" * 64
)  # a well-formed pin for the validate hook (the hash is only compared in wrangler.yml)


def role_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "publishing_gate_logical_id": "publisher",
        "publishing_gate_user": USER,
        "publishing_gate_group": USER,
        "publishing_gate_root": str(tmp_path / "var"),
        "publishing_gate_config_dir": str(tmp_path / "etc"),
        "publishing_gate_cred_src_dir": str(tmp_path / "etc" / "credentials"),
        "publishing_gate_export_dir": str(tmp_path / "export"),
        "publishing_gate_root_owner": USER,
    }
    v.update(kw)
    return v


def good(tmp_path: Path) -> dict:
    return role_vars(tmp_path)


def test_validate_passes_for_the_defaults(tmp_path):
    r = run_role(tmp_path, ROLE, "validate", good(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"publishing_gate_wrangler_version": "latest"},
        {"publishing_gate_wrangler_version": "^4.157.0"},
        {"publishing_gate_wrangler_version": "4.157"},
        {"publishing_gate_wrangler_version": "4.157.0-beta.1"},
        {"publishing_gate_wrangler_version": "@latest"},
        {"publishing_gate_pages_project": "site-x"},  # a Pages project needs the pinned lockfile
        {
            "publishing_gate_pages_project": "site-x",
            "publishing_gate_wrangler_lock_src": "/x/package-lock.json",
            "publishing_gate_wrangler_lock_sha256": "not-hex",
        },
        {"publishing_gate_mode": "yolo"},
        {"publishing_gate_tlp_allowed": "amber"},
        {"publishing_gate_tlp_allowed": "green"},  # green needs community and an access control
        {"publishing_gate_tlp_allowed": "green", "publishing_gate_audience": "community"},
        {"publishing_gate_deny_list_ref": "a-value-not-a-reference"},
        {"publishing_gate_pages_cred": "secret:Bad Name"},
        {"publishing_gate_feed_public_base_url": "http://cdn.example.test"},
        {"publishing_gate_root": "/var/lib/../etc"},
        {"publishing_gate_pages_branch": ""},
        {"publishing_gate_mode": "live"},  # live with no destination
    ],
)
def test_validate_refuses_what_cannot_be_honoured(tmp_path, over):
    r = run_role(tmp_path, ROLE, "validate", {**good(tmp_path), **over})
    assert r.returncode != 0, r.stdout


def test_validate_accepts_a_pinned_pages_project_and_a_community_green_publication(tmp_path):
    v = {
        **good(tmp_path),
        "publishing_gate_pages_project": "site-x",
        "publishing_gate_wrangler_lock_src": "/x/package-lock.json",
        "publishing_gate_wrangler_lock_sha256": LOCK_PIN,
        "publishing_gate_tlp_allowed": "green",
        "publishing_gate_audience": "community",
        "publishing_gate_access_control": "members-only",
        "publishing_gate_mode": "live",
    }
    r = run_role(tmp_path, ROLE, "validate", v)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_upgrade_hook_refuses_latest_and_the_same_version(tmp_path):
    for target in ("latest", "4.157.0", "^5.0.0"):
        v = {**good(tmp_path), "publishing_gate_target_wrangler_version": target}
        (tmp_path / "var" / "state").mkdir(parents=True, exist_ok=True)
        assert run_role(tmp_path, ROLE, "upgrade", v).returncode != 0, target


def test_credentials_are_written_by_name_0600_and_only_what_the_mode_needs(tmp_path):
    env = {
        "HNX_SECRET_PUBLISHING_DENY_LIST": "internal.example.test\n",
        "HNX_SECRET_PUBLISHING_CLOUDFLARE_API_TOKEN": "t" * 12,
        "HNX_SECRET_PUBLISHING_R2_ACCESS_KEY_ID": "i" * 8,
        "HNX_SECRET_PUBLISHING_R2_SECRET_ACCESS_KEY": "s" * 12,
    }
    creds = tmp_path / "etc" / "credentials"
    creds.mkdir(parents=True)
    r = run_role(tmp_path, ROLE, "credentials", good(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(p.name for p in creds.iterdir()) == ["deny-list"]  # stage: the deny-list alone
    assert oct((creds / "deny-list").stat().st_mode & 0o777) == "0o600"
    assert "t" * 12 not in r.stdout

    live = {**good(tmp_path), "publishing_gate_mode": "live"}
    r = run_role(tmp_path, ROLE, "credentials", live, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(p.name for p in creds.iterdir()) == [
        "cloudflare-api-token",
        "deny-list",
        "r2-access-key-id",
        "r2-secret-access-key",
    ]
    assert {oct(p.stat().st_mode & 0o777) for p in creds.iterdir()} == {"0o600"}
    again = run_role(tmp_path, ROLE, "credentials", live, env=env)
    assert "changed=0" in again.stdout, again.stdout


def test_the_configuration_holds_no_secret_and_names_the_pin(tmp_path):
    v = {
        **good(tmp_path),
        "publishing_gate_pages_project": "site-x",
        "publishing_gate_wrangler_lock_sha256": LOCK_PIN,
        "publishing_gate_wrangler_lock_src": "/x/package-lock.json",
        "publishing_gate_r2_bucket": "podcast",
        "publishing_gate_cloudflare_account_id": "acct1",
        "publishing_gate_feed_public_base_url": "https://cdn.example.test",
        "publishing_gate_feed_title": "T",
        "publishing_gate_feed_description": "D",
        "publishing_gate_feed_author": "A",
        "publishing_gate_feed_owner_email": "a@example.test",
    }
    (tmp_path / "etc").mkdir()
    r = run_role(tmp_path, ROLE, "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = json.loads((tmp_path / "etc" / "publishing.json").read_text())
    assert cfg["mode"] == "stage" and cfg["pages"]["branch"] == "pages"
    assert cfg["pages"]["wrangler_version"] == "4.157.0" and cfg["pages"]["lock_sha256"] == LOCK_PIN
    assert cfg["credentials_dir"] == str(tmp_path / "etc" / "credentials")
    text = json.dumps(cfg).lower()
    assert "token" not in text and "secret" not in text and "password" not in text


def test_the_export_restore_pair_round_trips_and_never_overwrites_history(tmp_path):
    state = tmp_path / "var" / "state"
    state.mkdir(parents=True)
    (tmp_path / "export").mkdir()
    (state / "published-manifest.jsonl").write_text('{"adapter": "pages"}\n')
    r = run_role(tmp_path, ROLE, "export", good(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "export" / "published-manifest.sha256").exists()
    # restore onto a live, non-empty manifest is refused
    v = {**good(tmp_path), "publishing_gate_restore_source": str(tmp_path / "export")}
    assert run_role(tmp_path, ROLE, "restore", v).returncode != 0
    # onto an empty one it succeeds, and a tampered export is refused
    (state / "published-manifest.jsonl").unlink()
    assert run_role(tmp_path, ROLE, "restore", v).returncode == 0
    assert (state / "published-manifest.jsonl").read_text() == '{"adapter": "pages"}\n'
    (state / "published-manifest.jsonl").unlink()
    (tmp_path / "export" / "published-manifest.jsonl").write_text("tampered\n")
    assert run_role(tmp_path, ROLE, "restore", v).returncode != 0


def _lock(tmp_path: Path, version: str = "4.157.0") -> tuple[Path, str]:
    import hashlib

    path = tmp_path / "lock" / "package-lock.json"
    path.parent.mkdir(exist_ok=True)
    text = json.dumps({"packages": {"node_modules/wrangler": {"version": version}}})
    path.write_text(text)
    return path, hashlib.sha256(text.encode()).hexdigest()


def _tools(tmp_path: Path) -> tuple[dict, dict]:
    """Fake npm (it lays down what `npm ci` would) and fake node (it prints what wrangler would)."""
    from rolerun import fake

    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    fake(
        bindir / "npm",
        "import json, os, sys\n"
        "assert sys.argv[1:2] == ['ci'] and '--ignore-scripts' in sys.argv, sys.argv\n"
        "os.makedirs('node_modules/wrangler', exist_ok=True)\n"
        "open('node_modules/wrangler/package.json', 'w').write(json.dumps({'version': '4.157.0'}))\n",
    )
    fake(bindir / "node", "print('wrangler 4.157.0')\n")
    return {
        "publishing_gate_npm": str(bindir / "npm"),
        "publishing_gate_node": str(bindir / "node"),
    }, {"PATH": f"{bindir}:{os.environ['PATH']}"}


def test_the_role_installs_only_the_pinned_lockfile_and_reads_the_version_back(tmp_path):
    lock, pin = _lock(tmp_path)
    tools, env = _tools(tmp_path)
    (tmp_path / "var" / "tools").mkdir(parents=True)
    v = {
        **good(tmp_path),
        **tools,
        "publishing_gate_pages_project": "site-x",
        "publishing_gate_wrangler_lock_src": str(lock),
        "publishing_gate_wrangler_lock_sha256": pin,
    }
    r = run_role(tmp_path, ROLE, "wrangler", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    tools_dir = tmp_path / "var" / "tools"
    assert (tools_dir / "package-lock.json").read_text() == lock.read_text()
    manifest = json.loads((tools_dir / "package.json").read_text())
    assert manifest["dependencies"] == {"wrangler": "4.157.0"}  # exact, never a range or latest
    again = run_role(tmp_path, ROLE, "wrangler", v, env=env)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout  # no reinstall


def test_the_role_refuses_a_lockfile_that_is_not_the_pinned_one_before_installing_anything(
    tmp_path,
):
    lock, _pin = _lock(tmp_path)
    tools, env = _tools(tmp_path)
    (tmp_path / "var" / "tools").mkdir(parents=True)
    base = {**good(tmp_path), **tools, "publishing_gate_pages_project": "site-x"}
    base["publishing_gate_wrangler_lock_src"] = str(lock)
    # the file's bytes do not hash to the pin (a swapped dependency)
    r = run_role(
        tmp_path,
        ROLE,
        "wrangler",
        {**base, "publishing_gate_wrangler_lock_sha256": "b" * 64},
        env=env,
    )
    assert r.returncode != 0 and not (tmp_path / "var" / "tools" / "package-lock.json").exists()
    # the right bytes, but a lockfile that pins another wrangler than the configured version
    (tmp_path / "o").mkdir()
    other, other_pin = _lock(tmp_path / "o", version="4.160.0")
    r = run_role(
        tmp_path,
        ROLE,
        "wrangler",
        {
            **base,
            "publishing_gate_wrangler_lock_src": str(other),
            "publishing_gate_wrangler_lock_sha256": other_pin,
        },
        env=env,
    )
    assert r.returncode != 0 and not (tmp_path / "var" / "tools" / "package-lock.json").exists()


def _readiness_bins(tmp_path: Path) -> dict:
    from rolerun import fake

    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    fake(b / "hnx", "pass\n")
    fake(b / "node", "print('v22.4.0')\n")
    fake(b / "npm", "pass\n")
    return {
        "publishing_gate_hnx_bin": str(b / "hnx"),
        "publishing_gate_node": str(b / "node"),
        "publishing_gate_npm": str(b / "npm"),
    }


def test_readiness_names_the_unset_secret_reference_and_never_a_value(tmp_path):
    v = {
        **good(tmp_path),
        **_readiness_bins(tmp_path),
        "publishing_gate_mode": "live",
        "publishing_gate_r2_bucket": "podcast",
        "publishing_gate_cloudflare_account_id": "acct1",
        "publishing_gate_feed_public_base_url": "https://cdn.example.test",
        "publishing_gate_feed_title": "T",
        "publishing_gate_feed_description": "D",
        "publishing_gate_feed_author": "A",
        "publishing_gate_feed_owner_email": "a@example.test",
    }
    env = {"HNX_SECRET_PUBLISHING_DENY_LIST": SECRET_VALUE}  # the others are unset
    r = run_role(tmp_path, ROLE, "readiness", v, env=env)
    assert r.returncode != 0
    out = r.stdout + r.stderr
    assert (
        "secret:publishing/cloudflare-api-token" in out
        and "secret:publishing/r2-access-key-id" in out
    )
    assert (
        "secret:publishing/deny-list"
        not in out.split("not set in the secret store:")[1].split("\n")[0]
    )
    assert SECRET_VALUE not in out
    # with every one set it passes
    env.update(
        HNX_SECRET_PUBLISHING_CLOUDFLARE_API_TOKEN="t" * 12,
        HNX_SECRET_PUBLISHING_R2_ACCESS_KEY_ID="i" * 8,
        HNX_SECRET_PUBLISHING_R2_SECRET_ACCESS_KEY="s" * 12,
    )
    r = run_role(tmp_path, ROLE, "readiness", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_stage_mode_readiness_needs_only_the_deny_list(tmp_path):
    v = {**good(tmp_path), **_readiness_bins(tmp_path)}
    r = run_role(tmp_path, ROLE, "readiness", v, env={})
    assert r.returncode != 0 and "secret:publishing/deny-list" in r.stdout + r.stderr
    r = run_role(tmp_path, ROLE, "readiness", v, env={"HNX_SECRET_PUBLISHING_DENY_LIST": "x"})
    assert r.returncode == 0, r.stdout + r.stderr
