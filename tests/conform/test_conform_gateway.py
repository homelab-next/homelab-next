# SPDX-License-Identifier: Apache-2.0
"""The ``inference`` suite through an LLM gateway, offline.

The lab's shipped target files (``compose/lab-in-a-box/targets/inference-gateway*.yml``) run the
whole suite, through :mod:`homelabnext.conform.adapters.llm_gateway`, against the fake OpenAI
server in gateway mode; then each ``gateway`` check is shown to fail on the defect it exists for,
using the shapes recorded from the real products in the ADR-0022 evidence run (LiteLLM without
Postgres: ``400 No connected db.``; Bifrost: provider-prefixed ``/v1/models`` ids).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conformance.fakes.inference_target import TlpGatewayServer
from conformance.fakes.openai_server import FakeOpenAIServer
from conformance.protocols.inference import GatewayClient, TlpAdmitGateway
from conformance.suites.inference import SUITE
from homelabnext import tlp
from homelabnext.conform import run_capability
from homelabnext.conform.adapters import llm_gateway
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.adapters.openai_compat import InferenceError, OpenAICompat
from homelabnext.conform.target import load_target
from homelabnext.registry.model import secret_env_name

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ROOT / "compose" / "lab-in-a-box" / "targets"
ADMIN = "sk-fake-master-key-0000"
THROTTLE = "sk-fake-throttle-0000"
#: the aliases of schemas/platform/examples/model_roles.valid.json
ROLES = ["embedder", "fast-classifier", "main-reasoner"]
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
    ],
)
def test_the_lab_targets_pass_every_check_against_a_conforming_gateway(monkeypatch, target, var):
    srv = gateway(monkeypatch, var=var)
    try:
        run = run_capability("inference", str(TARGETS / target))
        assert run.error is None, run.error
        assert sorted(r.check for r in run.results if not r.ok) == []
        assert {r.check for r in run.results} >= set(GATEWAY_CHECKS)
        # nothing skipped but the turn-records checks (the lab targets name no window known to
        # hold turns yet; follow-up: a recorded call per lab run, docs/orchestration-telemetry.md),
        # the tlp-ceiling check (the lab's gateway has no role that leaves the lab) and the
        # tlp-admit checks (LiteLLM cannot read a request's X-HNX-TLP label)
        skipped = {r.check for r in run.results if r.status != "pass"}
        assert {r.status for r in run.results if r.check in skipped} <= {"skip"}
        assert skipped == {
            s.id
            for s in SUITE.specs
            if {"turn-records", "tlp-ceiling", "tlp-admit"} & set(s.requires)
        }
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
    with pytest.raises(AdapterConfigError, match="go together"):
        llm_gateway.make(roles=roles, over_ceiling_key="secret:llm-gateway/key-x")
    with pytest.raises(AdapterConfigError, match="cannot read the role table"):
        llm_gateway.make(roles=str(tmp_path / "missing.json"))


def test_target_files_name_no_url_and_no_literal_secret():
    for path in TARGETS.glob("inference-gateway*.yml"):
        text = path.read_text()
        cfg = load_target(str(path)).binding("inference").config
        assert all(not str(v).startswith(("http://", "https://")) for v in cfg.values()), path
        assert str(cfg["throttle_key"]).startswith("secret:"), path
        assert "sk-" not in text, path


OVER = "sk-fake-over-ceiling-0000"
CEILING_CHECK = "gateway-refuses-role-above-key-ceiling"


def _ceiling_target(monkeypatch, key_models):
    """A gateway target with feature tlp-ceiling: OVER is an amber-ceiling key the gateway should
    scope to fast-classifier (a local role) and away from main-reasoner (here, the cloud role)."""
    srv = FakeOpenAIServer(
        models=ROLES, api_keys=[ADMIN, THROTTLE, OVER], key_limits={THROTTLE: 3},
        key_models=key_models,
    ).start()  # fmt: skip
    monkeypatch.setenv("HNX_ENDPOINT_LLM_GATEWAY", srv.url)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_MASTER_KEY", ADMIN)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_KEY_OVER", OVER)
    t = llm_gateway.make(
        roles="schemas/platform/examples/model_roles.valid.json",
        over_ceiling_key="secret:llm-gateway/key-over",
        over_ceiling_model="main-reasoner",
        over_ceiling_served="fast-classifier",
        allow_plaintext=True,
    )
    return srv, t


def test_a_key_scoped_away_from_a_role_above_its_ceiling_passes(monkeypatch):
    srv, t = _ceiling_target(monkeypatch, {OVER: ["fast-classifier"]})
    try:
        _, refused, served = t.over_ceiling()
        assert (refused, served) == ("main-reasoner", "fast-classifier")
        result = SUITE.bind(CEILING_CHECK, features=["tlp-ceiling"])(t)
        assert result.status == "pass", result
    finally:
        srv.stop()


@pytest.mark.parametrize(
    "key_models",
    [
        {},  # the key reaches every role: the ceiling is not applied
        {OVER: ["main-reasoner"]},  # scoped backwards: refused where it may call
    ],
)
def test_a_gateway_that_ignores_the_ceiling_fails_the_ceiling_check(monkeypatch, key_models):
    srv, t = _ceiling_target(monkeypatch, key_models)
    try:
        result = SUITE.bind(CEILING_CHECK, features=["tlp-ceiling"])(t)
        assert not result.ok and result.status != "skip", result
    finally:
        srv.stop()


def test_the_ceiling_check_needs_its_configuration(monkeypatch):
    srv = gateway(monkeypatch)
    try:
        t = llm_gateway.make(roles="schemas/platform/examples/model_roles.valid.json")
        with pytest.raises(AdapterConfigError, match="tlp-ceiling needs"):
            t.over_ceiling()
    finally:
        srv.stop()


# --- the lab's own gateway: feature tlp-admit, and its target on the conformance spec -----------
CONFORMANCE = ROOT / "compose" / "lab-in-a-box" / "config" / "llm-gateway-conformance"
OWN_TARGET = TARGETS / "inference-own-gateway.yml"
CLEAR_KEY = "sk-fake-clear-sender-0000"
TLP_CHECKS = [s.id for s in SUITE.specs if "tlp-admit" in s.requires]


class HeaderRecorder(FakeOpenAIServer):
    """Records every POST's X-HNX-TLP and X-HNX-Tag fields, as the server received them."""

    def gate(self, headers, path, model):
        self.seen = [(n, v) for n, v in headers.items() if n.lower().startswith("x-hnx-")]
        return None


def test_chat_fields_sends_each_field_on_its_own_and_refuses_a_line_break():
    with HeaderRecorder(models=["m"]) as srv:
        c = OpenAICompat(srv.url)
        tlp = [("X-HNX-TLP", ""), ("X-HNX-TLP", "clear"), ("X-HNX-Tag", "run-1")]
        assert c.chat_fields("m", PROMPT_MSG, tlp).model == "m"
        assert srv.seen == [("X-HNX-TLP", ""), ("X-HNX-TLP", "clear"), ("X-HNX-Tag", "run-1")]
        c.chat_fields("m", PROMPT_MSG, [])
        assert srv.seen == []
        for bad in ([("X-HNX-TLP", "clear\r\nX-Evil: 1")], [("X HNX", "clear")]):
            with pytest.raises(ValueError):
                c.chat_fields("m", PROMPT_MSG, bad)


def test_chat_fields_reads_the_error_envelopes_code():
    class Refuser(FakeOpenAIServer):
        def gate(self, headers, path, model):
            return 403, "tlp refused (unlabelled): no label"

    with Refuser(models=["m"]) as srv, pytest.raises(InferenceError) as exc:
        OpenAICompat(srv.url).chat_fields("m", PROMPT_MSG, [])
    assert (exc.value.status, exc.value.path) == (403, "/v1/chat/completions")
    assert exc.value.detail.startswith("tlp refused (unlabelled)")


PROMPT_MSG = [{"role": "user", "content": "hello"}]


def _own_config():
    return load_target(str(OWN_TARGET)).binding("inference").config


def _tlp_target(monkeypatch, **server):
    cfg = _own_config()
    roles = json.loads((ROOT / cfg["roles"]).read_text())["roles"]
    kw = {
        "models": sorted(roles),
        "api_keys": [ADMIN, CLEAR_KEY],
        "key_models": {CLEAR_KEY: [cfg["tlp_model"], cfg["tlp_local_model"]]},
        "leaving": {cfg["tlp_model"]: tlp.Label.CLEAR},
        "key_ceilings": {ADMIN: tlp.Label.RED, CLEAR_KEY: tlp.Label.CLEAR},
    }
    srv = TlpGatewayServer(**(kw | server)).start()
    monkeypatch.setenv("HNX_ENDPOINT_LLM_GATEWAY", srv.url)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_MASTER_KEY", ADMIN)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_CLEAR", CLEAR_KEY)
    keep = ("roles", "model", "tlp_sender_key", "tlp_model", "tlp_local_model", "failover_model")
    return srv, llm_gateway.make(**{k: cfg[k] for k in keep})


def test_the_adapter_runs_the_tlp_admit_checks_through_the_target_config(monkeypatch):
    srv, t = _tlp_target(monkeypatch)
    try:
        assert isinstance(t, TlpAdmitGateway)
        results = [SUITE.bind(c, features=["gateway", "tlp-admit"])(t) for c in TLP_CHECKS]
        assert [(r.check, r.status) for r in results if r.status != "pass"] == []
        sent = [r for r in srv.requests if r["path"] == "/v1/chat/completions"]
        assert {r["body"]["model"] for r in sent} >= {"cloud-reasoner", "failover"}
    finally:
        srv.stop()


def test_a_gateway_that_reads_the_admin_ceiling_as_clear_fails_through_the_adapter(monkeypatch):
    srv, t = _tlp_target(monkeypatch, key_ceilings={ADMIN: tlp.Label.CLEAR})
    try:
        r = SUITE.bind("tlp-admit-judged-at-key-ceiling", features=["gateway", "tlp-admit"])(t)
        assert r.status == "fail" and "expected an error" in r.evidence, r
    finally:
        srv.stop()


def test_the_tlp_admit_and_turn_records_features_need_their_configuration(monkeypatch):
    srv = gateway(monkeypatch)
    try:
        t = llm_gateway.make(roles="schemas/platform/examples/model_roles.valid.json")
        with pytest.raises(AdapterConfigError, match="tlp-admit needs"):
            t.tlp_admit()
        assert t.refused_fallback() is None
        with pytest.raises(AdapterConfigError, match="turn-records needs"):
            t.turn_records()
        with pytest.raises(AdapterConfigError, match="go together"):
            llm_gateway.make(
                roles="schemas/platform/examples/model_roles.valid.json",
                tlp_sender_key="secret:llm-gateway/key-x",
            )
        with pytest.raises(AdapterConfigError, match="embed_model: 'nope' is not a role"):
            llm_gateway.make(
                roles="schemas/platform/examples/model_roles.valid.json", embed_model="nope"
            )
    finally:
        srv.stop()


def test_the_own_gateway_target_agrees_with_the_conformance_gateway_config():
    """The own gateway's target names keys and roles of the rendered conformance config, each of
    the kind its check needs: the plain client's roles stay in the lab (it sends no X-HNX-TLP)."""
    t = load_target(str(OWN_TARGET)).binding("inference")
    assert set(t.features) == {
        "streaming",
        "embeddings",
        "gateway",
        "tlp-ceiling",
        "tlp-admit",
        "turn-records",
    }  # fmt: skip  (ADR-0038 decision 7's acceptance run)
    cfg = t.config
    doc = json.loads((CONFORMANCE / "gateway" / "gateway.json").read_text())
    table = json.loads((ROOT / cfg["roles"]).read_text())["roles"]
    roles, keys = doc["roles"], {k["key_env"]: k for k in doc["keys"]}
    assert doc["conformance_only"] is True and sorted(roles) == sorted(table)

    def key(ref):
        return keys[secret_env_name(ref)]

    for opt in ("model", "embed_model", "throttle_model", "tlp_local_model", "over_ceiling_served"):
        assert roles[cfg[opt]]["leaves_lab"] is False, opt
    assert (
        roles[cfg["model"]]["kind"] == "chat" and roles[cfg["embed_model"]]["kind"] == "embedding"
    )
    throttle = key(cfg["throttle_key"])
    assert throttle["limits"]["max_requests"] == cfg["throttle_requests"]
    assert cfg["throttle_model"] in throttle["roles"]
    over = key(cfg["over_ceiling_key"])
    assert tlp.read(over["tlp_ceiling"]) > tlp.read(roles[cfg["over_ceiling_model"]]["tlp_ceiling"])
    assert cfg["over_ceiling_model"] not in over["roles"]
    assert cfg["over_ceiling_served"] in over["roles"]
    leaving = roles[cfg["tlp_model"]]
    assert leaving["leaves_lab"] is True and leaving["tlp_ceiling"] in ("clear", "green")
    sender = key(cfg["tlp_sender_key"])
    assert sender["tlp_ceiling"] == "clear"
    assert {cfg["tlp_model"], cfg["tlp_local_model"]} <= set(sender["roles"])
    # the failover role: its deployment fails, its first fallback is refused by its own token
    # limit (below any reservation) and is never a model the fake serves, a later one serves
    failover = roles[cfg["failover_model"]]
    first, *later = failover["fallbacks"]
    assert later and roles[first]["limits"]["max_tokens"] == 1
    assert doc["telemetry_reader"]["key_env"] == secret_env_name(cfg["telemetry_key"])
    assert all(not str(v).startswith(("http://", "https://")) for v in cfg.values())
    assert "sk-" not in OWN_TARGET.read_text()


class TagRecorder(TlpGatewayServer):
    """The TLP fake that also records each chat's X-HNX-Tag and whether it was refused."""

    def gate(self, headers, path, model):
        verdict = super().gate(headers, path, model)
        self.tagged = getattr(self, "tagged", [])
        self.tagged.append((model, headers.get_all("X-HNX-Tag"), verdict is None))
        return verdict


def test_turn_records_sends_tagged_calls_once_a_run_and_names_their_window(monkeypatch):
    from homelabnext.conform.adapters.gateway_usage import UsageTurnSource

    cfg = _own_config()
    roles = json.loads((ROOT / cfg["roles"]).read_text())["roles"]
    srv = TagRecorder(
        models=sorted(roles),
        api_keys=[ADMIN, CLEAR_KEY],
        key_models={CLEAR_KEY: [cfg["tlp_model"], cfg["tlp_local_model"]]},
        leaving={cfg["tlp_model"]: tlp.Label.CLEAR},
        key_ceilings={ADMIN: tlp.Label.RED, CLEAR_KEY: tlp.Label.CLEAR},
    ).start()
    monkeypatch.setenv("HNX_ENDPOINT_LLM_GATEWAY", srv.url)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_MASTER_KEY", ADMIN)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_CLEAR", CLEAR_KEY)
    monkeypatch.setenv("HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER", "sk-fake-reader-0000")
    keep = ("roles", "model", "tlp_sender_key", "tlp_model", "tlp_local_model", "telemetry_key")
    try:
        source, start, end, tags = llm_gateway.make(**{k: cfg[k] for k in keep}).turn_records()
        again = llm_gateway.make(**{k: cfg[k] for k in keep}).turn_records()
        assert isinstance(source, UsageTurnSource) and again[0] is source  # sent once a run
        assert start < end and len(set(tags)) == 2
        assert srv.tagged == [
            (cfg["model"], [tags[0]], True),
            (cfg["model"], [tags[0]], True),
            (cfg["model"], [tags[1]], True),
            (cfg["tlp_model"], [tags[1]], False),  # refused: unlabelled to a role that leaves
            (cfg["tlp_model"], [tags[1]], False),
        ]
    finally:
        srv.stop()
