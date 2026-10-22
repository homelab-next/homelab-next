# SPDX-License-Identifier: Apache-2.0
"""The ``hnx_secret`` lookup plugin, called directly (the product roles exercise it end to end)."""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("ansible.errors")  # the repo's own ansible/ dir also imports as "ansible"
from ansible.errors import AnsibleLookupError

from homelabnext.registry.model import secret_env_name

PLUGIN = Path(__file__).resolve().parents[2] / "ansible/plugins/lookup/hnx_secret.py"


@pytest.fixture
def mod(monkeypatch):
    monkeypatch.delenv("BAO_ADDR", raising=False)
    spec = importlib.util.spec_from_file_location("hnx_secret", PLUGIN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_env_name_matches_the_registry_rule(mod):
    for ref in ("secret:siem/enrollment-password", "secret:a.b_c/d-token"):
        assert mod.env_name(ref) == secret_env_name(ref)


def test_environment_first_then_the_secrets_dir(mod, tmp_path, monkeypatch):
    (tmp_path / "siem").mkdir()
    (tmp_path / "siem" / "enrollment-password").write_text("from-file-fake\n")
    run = mod.LookupModule().run
    assert run(["secret:siem/enrollment-password"], {"hnx_secrets_dir": str(tmp_path)}) == [
        "from-file-fake"
    ]
    monkeypatch.setenv("HNX_SECRET_SIEM_ENROLLMENT_PASSWORD", "from-env-fake")
    assert run(["secret:siem/enrollment-password"], {"hnx_secrets_dir": str(tmp_path)}) == [
        "from-env-fake"
    ]


@pytest.mark.parametrize(
    ("ref", "message"),
    [
        ("plain-value-fake", "is not a secret reference"),
        ("secret:../etc/passwd", "is not a secret reference"),
        ("secret:a/../../b-token", "is not a secret reference"),
        ("secret:siem/token\n", "is not a secret reference"),  # "$" took a final newline
        ("secret:missing/token", "secret:missing/token is not set"),
    ],
)
def test_refusals(mod, tmp_path, ref, message):
    with pytest.raises(AnsibleLookupError, match=message):
        mod.LookupModule().run([ref], {"hnx_secrets_dir": str(tmp_path)})


def test_an_empty_secret_is_not_set(mod, tmp_path):
    (tmp_path / "blank").write_text("\n")
    with pytest.raises(AnsibleLookupError, match="is not set"):
        mod.LookupModule().run(["secret:blank-token"], {"hnx_secrets_dir": str(tmp_path)})


# ---- colliding environment names ---------------------------------------------------------------


@pytest.mark.parametrize(
    "other", ["secret:siem-enrollment/password", "secret:siem.enrollment/password"]
)
def test_two_references_in_one_variable_are_refused(mod, monkeypatch, other):
    monkeypatch.setenv("HNX_SECRET_SIEM_ENROLLMENT_PASSWORD", "fake-shared-value")
    run = mod.LookupModule().run
    with pytest.raises(
        AnsibleLookupError, match="both delivered in HNX_SECRET_SIEM_ENROLLMENT_PASSWORD"
    ):
        run(["secret:siem/enrollment-password", other], {})
    # and across two lookups of the same controller process
    assert run(["secret:siem/enrollment-password"], {}) == ["fake-shared-value"]
    with pytest.raises(AnsibleLookupError, match="rename one") as exc:
        run([other], {})
    assert "fake-shared-value" not in str(exc.value)


# ---- OpenBao -----------------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "overlay"))
from fake_openbao import FakeOpenBao, self_signed

VALUES = {
    "secret/siem/enrollment-password": {"value": "fake-enrollment-password"},
    "kv/idp/ldap-bind": {"pw": "fake-bind-password"},
}


@pytest.fixture
def tls(tmp_path):
    got = self_signed(tmp_path)
    if got is None:
        pytest.skip("openssl is not installed")
    return got


@pytest.fixture
def bao_env(monkeypatch):
    for k in ("BAO_TOKEN", "BAO_KV_MOUNT", "BAO_FIELD", "HNX_SECRET_SIEM_ENROLLMENT_PASSWORD"):
        monkeypatch.delenv(k, raising=False)

    def setup(bao, ca, **extra):
        env = {"BAO_ADDR": bao.url, "BAO_CACERT": str(ca), **extra}
        for k, v in env.items():
            monkeypatch.setenv(k, v)

    return setup


def test_openbao_by_name_with_approle_and_the_token_is_revoked(mod, tls, bao_env):
    server_ctx, ca = tls
    with FakeOpenBao(VALUES, tls=server_ctx) as bao:
        bao_env(bao, ca, BAO_ROLE_ID="fake-role", BAO_SECRET_ID="fake-secret-id")
        got = mod.LookupModule().run(["secret:siem/enrollment-password"], {})
        assert got == ["fake-enrollment-password"]
        assert bao.live == set()  # revoked right after the read
    assert [c[:2] for c in bao.calls] == [
        ("POST", "/v1/auth/approle/login"),
        ("GET", "/v1/secret/data/siem/enrollment-password"),
        ("POST", "/v1/auth/token/revoke-self"),
    ]


def test_openbao_wins_over_a_stray_environment_variable(mod, tls, bao_env, monkeypatch):
    server_ctx, ca = tls
    with FakeOpenBao(VALUES, tls=server_ctx) as bao:
        bao_env(bao, ca, BAO_ROLE_ID="fake-role", BAO_SECRET_ID="fake-secret-id")
        monkeypatch.setenv("HNX_SECRET_SIEM_ENROLLMENT_PASSWORD", "fake-stray-value")
        assert mod.LookupModule().run(["secret:siem/enrollment-password"], {}) == [
            "fake-enrollment-password"
        ]


def test_openbao_mount_field_and_a_given_token(mod, tls, bao_env):
    server_ctx, ca = tls
    with FakeOpenBao(VALUES, tls=server_ctx) as bao:
        bao.live.add("fake-given-token")
        bao_env(bao, ca, BAO_TOKEN="fake-given-token", BAO_KV_MOUNT="kv", BAO_FIELD="pw")
        assert mod.LookupModule().run(["secret:idp/ldap-bind"], {}) == ["fake-bind-password"]
        assert bao.live == {"fake-given-token"}  # a token we did not mint is not revoked
    assert [c[:2] for c in bao.calls] == [("GET", "/v1/kv/data/idp/ldap-bind")]


def test_openbao_redirect_is_refused_and_never_carries_the_token(mod, tls, bao_env):
    server_ctx, ca = tls
    with FakeOpenBao() as sink, FakeOpenBao(tls=server_ctx, redirect_to=sink.url) as bao:
        bao_env(bao, ca, BAO_TOKEN="fake-given-token")
        with pytest.raises(AnsibleLookupError, match=r"HTTP 307.*redirects are refused") as exc:
            mod.LookupModule().run(["secret:siem/enrollment-password"], {})
    assert sink.calls == [] and "fake-given-token" not in str(exc.value)


def test_openbao_missing_secret_still_revokes_and_names_no_value(mod, tls, bao_env):
    server_ctx, ca = tls
    with FakeOpenBao(VALUES, tls=server_ctx) as bao:
        bao_env(bao, ca, BAO_ROLE_ID="fake-role", BAO_SECRET_ID="fake-secret-id")
        with pytest.raises(AnsibleLookupError, match="HTTP 404"):
            mod.LookupModule().run(["secret:missing/token"], {})
        assert bao.live == set()


def test_openbao_failed_revoke_is_a_warning(mod, tls, bao_env, monkeypatch):
    server_ctx, ca = tls
    warned: list[str] = []
    monkeypatch.setattr(mod.display, "warning", warned.append)
    with FakeOpenBao(VALUES, tls=server_ctx, revoke_status=403) as bao:
        bao_env(bao, ca, BAO_ROLE_ID="fake-role", BAO_SECRET_ID="fake-secret-id")
        assert mod.LookupModule().run(["secret:siem/enrollment-password"], {}) == [
            "fake-enrollment-password"
        ]
    (line,) = warned
    assert "could not revoke" in line and "HTTP 403" in line
    assert "fake-minted-token" not in line and "fake-secret-id" not in line


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"BAO_ADDR": "http://bao.example.internal"}, "https://"),
        ({"BAO_ADDR": "https://bao.example.internal", "BAO_KV_MOUNT": "a/b"}, "mount name"),
        ({"BAO_ADDR": "https://bao.example.internal", "BAO_KV_MOUNT": "kv\n"}, "mount name"),
        ({"BAO_ADDR": "https://bao.example.internal"}, "BAO_ROLE_ID and BAO_SECRET_ID"),
    ],
)
def test_openbao_misconfiguration(mod, monkeypatch, env, message):
    for k in ("BAO_TOKEN", "BAO_ROLE_ID", "BAO_SECRET_ID", "BAO_KV_MOUNT"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(AnsibleLookupError, match=re.escape(message)):
        mod.LookupModule().run(["secret:siem/enrollment-password"], {})
