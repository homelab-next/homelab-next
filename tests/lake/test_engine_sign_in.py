# SPDX-License-Identifier: Apache-2.0
"""Lake readers sign in to the query engine (ADR-0033 decision 6; docs/modules/tlp.md#engine-sign-in).

``make_lake`` takes each reader's credential as a secret reference; the engine client sends it as
HTTP Basic for the reader's login on every request (the ``nextUri`` reads included), the catalog
client sends its bearer token, both through ``credential_opener``; and a ``lake-query`` endpoint
that is not loopback is refused without a credential, whatever else is passed."""

from __future__ import annotations

import base64

import pytest
from fake_lab import FakeLab

import homelabnext.conform.adapters.lake as adapter
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.lake import LakeError

OFF_HOST = "https://192.0.2.9:8443"  # no-raw-endpoint: allow RFC 5737 documentation address
READER = "analyzer:novelty"
SECRET = "secret:lake-query/readers/analyzer.novelty"
PASSWORD_VAR = "HNX_SECRET_LAKE_QUERY_READERS_ANALYZER_NOVELTY"
TOKEN_VAR = "HNX_SECRET_LAKE_CATALOG_TOKEN"


def _basic(login: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{login}:{password}".encode()).decode()


@pytest.fixture
def lab(monkeypatch):
    with FakeLab() as fl:
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", fl.url)
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", fl.url)
        monkeypatch.setenv(PASSWORD_VAR, "pw:with:colons")
        monkeypatch.setenv(TOKEN_VAR, "tok")
        yield fl


@pytest.fixture
def off_host(monkeypatch):
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", OFF_HOST)
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", OFF_HOST)
    monkeypatch.setenv(PASSWORD_VAR, "pw")


def _clients(**kw):
    kw = {"domain": "example.internal", "warehouse": "lab", "user": READER, **kw}
    return adapter.make_clients(**kw)


def _sent(lab, prefix):
    return [a for _, path, a in lab.auth if path.startswith(prefix)]


# ---------------------------------------------------------------- the login and the header
@pytest.mark.parametrize(
    ("user", "login"),
    [(READER, "analyzer.novelty"), ("profile:x", "profile.x"), ("hnx-conform", "hnx-conform")],
)
def test_a_reader_id_signs_in_with_its_colon_as_a_dot(user, login):
    assert adapter.engine_login(user) == login
    assert adapter.password_auth(user, lambda: "s3")() == _basic(login, "s3")
    assert adapter.reader_secret(user) == f"secret:{adapter.READERS}/{login}"


@pytest.mark.parametrize("user", ["a:b:c", "", "user:al ice", "x:\x00"])
def test_a_user_with_no_login_is_refused(user):
    with pytest.raises(LakeError, match="no engine login"):
        adapter.engine_login(user)


def test_an_empty_password_is_an_error_not_an_anonymous_request():
    with pytest.raises(LakeError, match="no password"):
        adapter.password_auth(READER, lambda: "")()


# ---------------------------------------------------------------- refusal without a credential
def test_a_non_loopback_engine_is_refused_without_a_credential(off_host):
    with pytest.raises(LakeError, match=r"not loopback.*must sign in") as got:
        adapter.make_lake(domain="example.internal", warehouse="lab", user=READER)
    assert SECRET in str(got.value)
    # allow_plaintext is about the scheme, not about signing in: it is no way around this, and a
    # catalog token alone does not sign the reader in to the engine
    for extra in ({"allow_plaintext": True}, {"catalog_credential": "secret:lake-catalog/token"}):
        with pytest.raises(LakeError, match="must sign in"):
            _clients(credential=None, **extra)


def test_a_non_loopback_engine_is_accepted_with_a_credential(off_host):
    engine, catalog = _clients(credential=SECRET)  # nothing is sent while they are built
    assert engine._auth() == _basic("analyzer.novelty", "pw")
    assert engine._opener is not None and engine._opener is catalog._opener


@pytest.mark.parametrize("value", ["pw", "secret:", "secret:UPPER", "", 3])
def test_a_credential_is_a_secret_name_never_a_value(lab, value):
    with pytest.raises(AdapterConfigError, match="secret name"):
        _clients(credential=value)


def test_an_unset_credential_fails_when_the_clients_are_built(lab, monkeypatch):
    monkeypatch.delenv(PASSWORD_VAR)
    with pytest.raises(AdapterConfigError, match=PASSWORD_VAR):
        _clients(credential=SECRET)


# ---------------------------------------------------------------- what goes on the wire
def test_with_a_credential_both_clients_sign_in_through_the_credential_opener(lab, monkeypatch):
    made = []
    real = adapter.credential_opener

    def spy(ca_file=None):
        made.append((ca_file, real(ca_file)))
        return made[-1][1]

    monkeypatch.setattr(adapter, "credential_opener", spy)
    engine, catalog = _clients(credential=SECRET, catalog_credential="secret:lake-catalog/token")
    assert [ca for ca, _ in made] == [None]
    assert engine._opener is made[0][1] and catalog._opener is made[0][1]
    with pytest.raises(LakeError):  # the fake has no such schema; the requests are what count
        engine.execute("SELECT 1")
    assert catalog.prefix
    sent = _sent(lab, "/v1/statement")
    assert len(sent) >= 2  # the statement and at least one nextUri read
    assert set(sent) == {_basic("analyzer.novelty", "pw:with:colons")}
    assert _sent(lab, "/catalog/") == ["Bearer tok"]


def test_the_password_is_read_again_at_every_request(lab, monkeypatch):
    engine, _ = _clients(credential=SECRET)
    for pw in ("one", "two"):
        monkeypatch.setenv(PASSWORD_VAR, pw)
        with pytest.raises(LakeError):
            engine.execute("SELECT 1")
    sent = _sent(lab, "/v1/statement")
    assert sent[0] == _basic("analyzer.novelty", "one")
    assert sent[-1] == _basic("analyzer.novelty", "two")


def test_a_loopback_lab_without_a_credential_sends_none(lab):
    engine, catalog = _clients(user="hnx-conform")
    assert engine._opener is None and catalog._opener is None
    with pytest.raises(LakeError):
        engine.execute("SELECT 1")
    assert catalog.prefix
    assert lab.auth and {a for _, _, a in lab.auth} == {None}


def test_every_engine_request_goes_through_the_injected_opener(lab):
    """The opener is not just held: the statement and every nextUri read are sent through it, so
    the credential opener's no-redirect, no-proxy rule covers the engine's requests."""
    import urllib.request

    opened = []

    class Spy(urllib.request.OpenerDirector):
        def open(self, req, *a, **kw):
            opened.append(req.full_url)
            return real.open(req, *a, **kw)

    real = adapter.credential_opener(None)
    engine, _ = _clients()
    engine._opener = Spy()
    with pytest.raises(LakeError):
        engine.execute("SELECT 1")
    statements = [p for _, p, _ in lab.auth if p.startswith("/v1/statement")]
    assert len(statements) >= 2 and len(opened) == len(statements)


# ---------------------------------------------------------------- what never goes out
def test_a_credential_never_goes_over_plaintext_to_another_host(monkeypatch):
    plain = "http://192.0.2.9:8080"  # no-raw-endpoint: allow RFC 5737 documentation address
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", plain)
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", plain)
    monkeypatch.setenv(PASSWORD_VAR, "pw")
    with pytest.raises(LakeError, match="https only"):
        _clients(credential=SECRET, allow_plaintext=True)


@pytest.mark.parametrize("token", ["s3cret\n", "s3 cret", "s3cret\x7f"])
def test_a_catalog_token_a_header_cannot_carry_is_refused_without_quoting_it(
    lab, monkeypatch, token
):
    _, catalog = _clients(credential=SECRET, catalog_credential="secret:lake-catalog/token")
    monkeypatch.setenv(TOKEN_VAR, token)
    with pytest.raises(LakeError, match="cannot carry") as got:
        catalog._auth()
    assert TOKEN_VAR in str(got.value)
    assert "s3" not in str(got.value)
