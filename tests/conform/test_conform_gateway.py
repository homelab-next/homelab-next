# SPDX-License-Identifier: Apache-2.0
"""The ``inference`` suite through an LLM gateway, offline.

The lab's shipped target files (``compose/lab-in-a-box/targets/inference-gateway*.yml``) run the
whole suite, through :mod:`homelabnext.conform.adapters.llm_gateway`, against the fake OpenAI
server in gateway mode; then each ``gateway`` check is shown to fail on the defect it exists for,
using the shapes recorded from the real products in the ADR-0022 evidence run (LiteLLM without
Postgres: ``400 No connected db.``; Bifrost: provider-prefixed ``/v1/models`` ids).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conformance.fakes.openai_server import FakeOpenAIServer
from conformance.protocols.inference import GatewayClient
from conformance.suites.inference import SUITE
from homelabnext.conform import run_capability
from homelabnext.conform.adapters import llm_gateway
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.target import load_target

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ROOT / "compose" / "lab-in-a-box" / "targets"
ADMIN = "sk-bf-fake-master-key-0000"
THROTTLE = "sk-bf-fake-throttle-0000"
ROLES = ["fast-classifier", "main-reasoner"]  # schemas/platform/examples/model_roles.valid.json
GATEWAY_CHECKS = [
    "gateway-rejects-bad-key",
    "gateway-limit-throttles",
    "gateway-models-match-roles",
]


class NoDatabaseGateway(FakeOpenAIServer):
    """LiteLLM with a master key and no Postgres, as recorded: a wrong key is 400 No connected db."""

    def admit(self, authorization, path=""):
        verdict = super().admit(authorization, path)
        if verdict and verdict[0] == 401:
            return 400, "No connected db."
        return verdict


class UnlimitedGateway(FakeOpenAIServer):
    """A gateway whose configured limit is not enforced."""

    def admit(self, authorization, path=""):
        verdict = super().admit(authorization, path)
        return None if verdict and verdict[0] == 429 else verdict


class OpenChatGateway(FakeOpenAIServer):
    """Guards /v1/models but serves chat to any key or none: the defect the bad-key check exists for."""

    def admit(self, authorization, path=""):
        return None if path.startswith("/v1/chat") else super().admit(authorization, path)


class DeadKeyGateway(FakeOpenAIServer):
    """The throttled key answers 429 from its first call: nothing is ever served on it."""

    def admit(self, authorization, path=""):
        if (authorization or "").endswith(THROTTLE):
            return 429, "rate limit exceeded"
        return super().admit(authorization, path)


class EarlyThrottleGateway(FakeOpenAIServer):
    """Throttles the key one call before its configured limit."""

    def admit(self, authorization, path=""):
        verdict = super().admit(authorization, path)
        throttled = (authorization or "").endswith(THROTTLE)
        if verdict is None and throttled and self._key_calls.get(THROTTLE, 0) >= 3:
            return 429, "rate limit exceeded"
        return verdict


def gateway(monkeypatch, cls=FakeOpenAIServer, models=ROLES, var="HNX_ENDPOINT_LLM_GATEWAY"):
    srv = cls(models=list(models), api_keys=[ADMIN, THROTTLE], key_limits={THROTTLE: 3}).start()
    monkeypatch.setenv(var, srv.url)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_MASTER_KEY", ADMIN)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_THROTTLE", THROTTLE)
    return srv


def failing(run):
    assert run.error is None, run.error
    return sorted(r.check for r in run.results if r.status != "pass")


@pytest.mark.parametrize(
    "target, var",
    [
        ("inference-gateway.yml", "HNX_ENDPOINT_LLM_GATEWAY"),
        ("inference-gateway-bifrost.yml", "HNX_ENDPOINT_LLM_GATEWAY_BIFROST"),
    ],
)
def test_the_lab_targets_pass_every_check_against_a_conforming_gateway(monkeypatch, target, var):
    srv = gateway(monkeypatch, var=var)
    try:
        run = run_capability("inference", str(TARGETS / target))
        assert run.error is None, run.error
        assert sorted(r.check for r in run.results if not r.ok) == []
        assert {r.check for r in run.results} >= set(GATEWAY_CHECKS)
        # nothing skipped but the turn-records checks: the lab targets name no window known to
        # hold turns yet (follow-up: a recorded call per lab run, docs/orchestration-telemetry.md)
        skipped = {r.check for r in run.results if r.status != "pass"}
        assert {r.status for r in run.results if r.check in skipped} <= {"skip"}
        assert skipped == {s.id for s in SUITE.specs if "turn-records" in s.requires}
    finally:
        srv.stop()


def test_the_target_is_a_gateway_client(monkeypatch):
    srv = gateway(monkeypatch)
    try:
        t = llm_gateway.make(roles="schemas/platform/examples/model_roles.valid.json")
        assert isinstance(t, GatewayClient)
        assert t.declared_models() == ROLES
        assert "sk-" not in repr(t)
    finally:
        srv.stop()


def test_no_database_gateway_fails_the_bad_key_check(monkeypatch):
    srv = gateway(monkeypatch, cls=NoDatabaseGateway)
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=GATEWAY_CHECKS
        )
        assert failing(run) == ["gateway-rejects-bad-key"]
        ev = next(r.evidence for r in run.results if r.check == "gateway-rejects-bad-key")
        assert "wrong key: HTTP 400 ('No connected db." in ev
    finally:
        srv.stop()


def test_a_401_that_blames_the_database_still_fails(monkeypatch):
    class DbBlame(FakeOpenAIServer):
        def admit(self, authorization, path=""):
            verdict = super().admit(authorization, path)
            return (401, "database unavailable") if verdict and verdict[0] == 401 else verdict

    srv = gateway(monkeypatch, cls=DbBlame)
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=GATEWAY_CHECKS
        )
        assert failing(run) == ["gateway-rejects-bad-key"]
    finally:
        srv.stop()


def test_unenforced_limit_fails_the_throttle_check(monkeypatch):
    srv = gateway(monkeypatch, cls=UnlimitedGateway)
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=GATEWAY_CHECKS
        )
        assert failing(run) == ["gateway-limit-throttles"]
    finally:
        srv.stop()


def test_a_gateway_that_serves_chat_to_any_key_fails_the_bad_key_check(monkeypatch):
    srv = gateway(monkeypatch, cls=OpenChatGateway)
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=["gateway-rejects-bad-key"]
        )
        assert failing(run) == ["gateway-rejects-bad-key"]
        ev = run.results[0].evidence
        assert "wrong key: expected an error" in ev
        chats = [r for r in srv.requests if r["path"] == "/v1/chat/completions"]
        assert chats, "the check never sent a chat call with the bad key"
    finally:
        srv.stop()


def test_the_bad_key_401_must_come_from_the_chat_call(monkeypatch):
    srv = gateway(monkeypatch)
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=["gateway-rejects-bad-key"]
        )
        assert failing(run) == []
        bad = [r for r in srv.requests if r["path"] == "/v1/chat/completions"]
        assert len(bad) == 2  # one wrong-key and one no-key chat call, both refused
    finally:
        srv.stop()


@pytest.mark.parametrize("cls", [DeadKeyGateway, EarlyThrottleGateway])
def test_a_limit_that_serves_fewer_than_n_fails_the_throttle_check(monkeypatch, cls):
    srv = gateway(monkeypatch, cls=cls)
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=["gateway-limit-throttles"]
        )
        assert failing(run) == ["gateway-limit-throttles"]
        assert "were not all served" in run.results[0].evidence
    finally:
        srv.stop()


def test_provider_prefixed_model_ids_fail_the_roles_check(monkeypatch):
    srv = gateway(monkeypatch, models=[f"hnx-inference-small/{m}" for m in ROLES])
    try:
        run = run_capability(
            "inference", str(TARGETS / "inference-gateway.yml"), only=["gateway-models-match-roles"]
        )
        assert failing(run) == ["gateway-models-match-roles"]
    finally:
        srv.stop()


def test_the_built_in_fake_target_declares_the_gateway_feature():
    run = run_capability("inference", "fake", only=GATEWAY_CHECKS)
    assert [r.status for r in run.results] == ["pass"] * 3


def test_adapter_configuration_errors(monkeypatch, tmp_path):
    monkeypatch.delenv("HNX_ENDPOINT_LLM_GATEWAY", raising=False)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_MASTER_KEY", ADMIN)
    roles = "schemas/platform/examples/model_roles.valid.json"
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_LLM_GATEWAY is not set"):
        llm_gateway.make(roles=roles)
    with pytest.raises(AdapterConfigError, match="go together"):
        llm_gateway.make(roles=roles, throttle_key="secret:llm-gateway/key-x")
    with pytest.raises(AdapterConfigError, match="cannot read the role table"):
        llm_gateway.make(roles=str(tmp_path / "missing.json"))


def test_target_files_name_no_url_and_no_literal_secret():
    for path in TARGETS.glob("inference-gateway*.yml"):
        text = path.read_text()
        cfg = load_target(str(path)).binding("inference").config
        assert all(not str(v).startswith(("http://", "https://")) for v in cfg.values()), path
        assert str(cfg["throttle_key"]).startswith("secret:"), path
        assert "sk-" not in text, path
