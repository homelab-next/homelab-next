# SPDX-License-Identifier: Apache-2.0
"""``hnx broker``: validate, and the documented walkthrough (docs/broker.md) through the CLI."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from homelabnext.broker.cli import main
from homelabnext.cli import main as hnx

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"


def test_validate_passes_on_the_example_and_fails_on_a_tampered_copy(tmp_path, capsys):
    assert hnx(["broker", "validate", str(EXAMPLE)]) == 0
    assert "ok (5 actions, 3 lanes)" in capsys.readouterr().out
    shutil.copytree(EXAMPLE.parent, tmp_path / "ex")
    h = tmp_path / "ex" / "handlers" / "service-restart.sh"
    h.write_text(h.read_text() + "\n# edited\n")
    assert main(["validate", str(tmp_path / "ex" / "manifest.yml"), "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and "handler_digest" in out["problems"][0]


def test_validate_unreadable_and_non_mapping(tmp_path, capsys):
    assert main(["validate", str(tmp_path / "missing.yml")]) == 2
    (tmp_path / "list.yml").write_text("- a\n")
    assert main(["validate", str(tmp_path / "list.yml")]) == 1
    capsys.readouterr()


def test_validate_shows_lane_usage_and_warns_near_the_quota(tmp_path, capsys):
    """A lane at its quota refused the agent alone: nothing showed the operator a lane directory
    filling up, nor one already over its quota on the day --data-root was pointed at it."""
    own = tmp_path / "data" / "memory" / "triage"
    own.mkdir(parents=True)
    for i in range(3500):  # 85% of the default 4096 files
        (own / f"n{i}.md").write_text("x")
    assert main(["validate", str(EXAMPLE), "--data-root", str(tmp_path / "data")]) == 0
    out = capsys.readouterr().out
    assert "lane memory memory/triage: 3500/4096 files" in out and "WARNING: over 80%" in out
    assert main(["validate", str(EXAMPLE), "--json", "--data-root", str(tmp_path / "data")]) == 0
    [row] = json.loads(capsys.readouterr().out)["lane_usage"]
    assert (row["lane"], row["files"], row["warn"]) == ("memory", 3500, True)


def test_validate_shows_each_agents_share_of_the_shared_inbox(tmp_path, capsys):
    inbox = tmp_path / "data" / "records" / "inbox"
    inbox.mkdir(parents=True)
    for i in range(500):  # 98% of triage's default share of 512 files
        (inbox / f"2026-01-15-triage-s{i}-0000000{i % 10}.md").write_text("x")
    assert main(["validate", str(EXAMPLE), "--data-root", str(tmp_path / "data")]) == 0
    out = capsys.readouterr().out
    assert "profile:triage: 500/512 files" in out and "WARNING: over 80% of its share" in out


def test_the_production_example_sets_its_append_only_findings_lane(capsys):
    from homelabnext.broker.service import load_manifest

    manifest, _ = load_manifest(EXAMPLE.parent / "manifest.production.yml")
    [findings] = [ld for ld in manifest["lanes"] if ld["name"] == "findings"]
    assert findings["max_files"] is None, "a file cap is a retention limit for append-only notes"
    assert findings["max_total_bytes"] >= 1 << 30 and findings["max_writes_per_hour"] >= 1


@pytest.fixture
def broker(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HNX_BROKER_MANIFEST", str(EXAMPLE))
    monkeypatch.setenv("HNX_BROKER_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("HNX_BROKER_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("HNX_BROKER_SECRET_DEMO_API_TOKEN", "fake-cli-token")

    def run(*argv, code=0, as_json=True):
        rc = main([argv[0], *(["--json"] if as_json else []), *argv[1:]])
        out = capsys.readouterr()
        assert rc == code, (rc, out.out, out.err)
        return json.loads(out.out) if as_json and out.out.strip() else out

    return run


def test_walkthrough(broker, tmp_path):
    note = '{"name":"queue-notes.md","content":"drains slowly\\n"}'
    rid = broker("submit", "memory.write", "--as", "profile:triage", "--params", note)["request_id"]
    assert (
        broker("run", rid, "--as", "profile:triage")["result"]["path"]
        == "memory/triage/queue-notes.md"
    )
    assert (tmp_path / "data/memory/triage/queue-notes.md").exists()
    bad = broker(
        "submit",
        "memory.write",
        "--as",
        "profile:triage",
        "--params",
        '{"name":"../../x.md","content":"x"}',
        code=1,
    )
    assert bad["error"] == "lane-name-invalid"
    req = broker(
        "submit",
        "service.restart",
        "--as",
        "profile:triage",
        "--target",
        "svc:queue",
        "--params",
        '{"grace_s": 30}',
    )
    assert req["awaiting_approval"] is True
    rid = req["request_id"]
    assert broker("run", rid, "--as", "profile:triage", code=1)["error"] == "approval-required"
    assert [r["request_id"] for r in broker("pending")] == [rid]
    assert broker("approve", rid, "--as", "sso:triage", code=1)["error"] == "approval-self-approved"
    assert (
        broker("approve", rid, "--as", "sso:operator-one", "--note", "ok")["decision"] == "approved"
    )
    out = broker("run", rid, "--as", "profile:triage")["result"]["output"]
    assert out == {"would_restart": "svc:queue", "token_present": True, "params": {"grace_s": 30}}
    assert broker("status", rid, "--as", "profile:triage")["state"] == "done"
    assert broker("status", rid, "--as", "profile:reader", code=1)["error"] == "not-request-owner"
    assert len(broker("audit", "--request", rid, "--outcome", "ok")) == 4
    assert len(broker("audit", "--tail", "2")) == 2 and broker("audit", "--tail", "0") == []
    text = broker("audit", "--operation", "approve", as_json=False).out
    assert "approval-self-approved" in text and "sso:operator-one" in text


def test_text_output_cancel_and_deny(broker, tmp_path):
    rid = broker(
        "submit",
        "service.restart",
        "--as",
        "profile:triage",
        "--params",
        '{"grace_s": 1}',
        as_json=False,
    ).out.split()[0]
    assert "nothing awaiting" not in broker("pending", as_json=False).out
    assert "denied" in broker("deny", rid, "--as", "sso:operator-one", as_json=False).out
    assert "nothing awaiting approval" in broker("pending", as_json=False).out
    params = tmp_path / "p.json"
    params.write_text('{"name":"a.md","content":"x"}')
    rid = broker(
        "submit",
        "memory.write",
        "--as",
        "profile:triage",
        "--params-file",
        str(params),
        as_json=False,
    ).out.split()[0]
    assert "pending" in broker("status", rid, "--as", "profile:triage", as_json=False).out
    assert "cancelled" in broker("cancel", rid, "--as", "profile:triage", as_json=False).out
    assert (
        "refused (not-pending)"
        in broker("run", rid, "--as", "profile:triage", code=1, as_json=False).err
    )


def test_usage_errors(broker, monkeypatch, capsys):
    assert (
        "must be a JSON object"
        in broker(
            "submit",
            "memory.write",
            "--as",
            "profile:triage",
            "--params",
            "[1]",
            code=2,
            as_json=False,
        ).err
    )
    monkeypatch.delenv("HNX_BROKER_STATE")
    with pytest.raises(SystemExit):
        main(["pending"])
    monkeypatch.setenv("HNX_BROKER_STATE", "x")
    monkeypatch.setenv(
        "HNX_BROKER_MANIFEST", str(ROOT / "schemas/broker/negative/manifest.default-allow.json")
    )
    assert main(["pending"]) == 2
    capsys.readouterr()


def test_serve_pages_through_ntfy_with_a_token_by_secret_reference(tmp_path, monkeypatch):
    """hnx broker serve built its service without a notifier: no approval page and no lane-quota
    notice ever fired in the shipped CLI."""
    import argparse

    from homelabnext.broker.cli import _service, notifier_from_args
    from homelabnext.notify import Message

    override = "https://n.svc.example.internal:8443"  # no-raw-endpoint: allow override syntax
    monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", override)
    monkeypatch.setenv("HNX_SECRET_BROKER_NTFY_TOKEN", "fake-ntfy-token-3c1")
    args = argparse.Namespace(
        manifest=str(EXAMPLE), state=str(tmp_path / "state"), data_root=None,
        approvals_url=None, notify_topic="broker", notify_token="secret:broker/ntfy-token",
        registry=None, cmd="serve",
    )  # fmt: skip
    svc = _service(args)
    assert svc.notifier is not None and svc._scoped, "per-agent budgets"
    req = svc.notifier.sender.build_request(Message(key="k", title="t", body="b"))
    assert req.full_url == f"{override}/broker"
    assert req.get_header("Authorization") == "Bearer fake-ntfy-token-3c1"
    assert "fake-ntfy-token-3c1" not in repr(vars(args))
    with pytest.raises(ValueError, match="secret reference"):
        notifier_from_args(argparse.Namespace(**{**vars(args), "notify_token": "fake-literal"}))
    assert notifier_from_args(argparse.Namespace(**{**vars(args), "notify_topic": None})) is None


def test_without_a_notifier_a_lane_quota_refusal_is_logged_once(tmp_path, caplog):
    from homelabnext.broker.service import BrokerService, load_manifest

    manifest, docs = load_manifest(EXAMPLE)
    manifest["lanes"][0]["max_files"] = 1
    svc = BrokerService(tmp_path / "s", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
                        data_root=tmp_path / "d")  # fmt: skip
    svc.call("profile:triage", "memory.write", {"name": "a.md", "content": "x"})
    with caplog.at_level("WARNING", logger="homelabnext.broker.service"):
        for name in ("b.md", "c.md", "d.md"):
            with pytest.raises(Exception, match="quota"):
                svc.call("profile:triage", "memory.write", {"name": name, "content": "x"})
    hits = [r for r in caplog.records if "refuses its writes" in r.getMessage()]
    assert len(hits) == 1 and hits[0].levelname == "WARNING"


def _notify_args(tmp_path, **over):
    import argparse

    doc = {"state": str(tmp_path / "state"), "notify_topic": "broker", "notify_topic_file": None,
           "notify_token": "secret:broker/ntfy-token", "registry": None}  # fmt: skip
    return argparse.Namespace(**{**doc, **over})


def test_serve_checks_its_notify_endpoint_at_start(tmp_path, monkeypatch, caplog):
    """A notifier that could never send started anyway: every page failed, leaving only an
    audit record, and a token could be configured over plaintext."""
    from homelabnext.broker.cli import NOTIFY_ALL_AGENTS_PER_HOUR, notifier_from_args

    monkeypatch.delenv("HNX_ENDPOINT_NOTIFY", raising=False)
    monkeypatch.setenv("HNX_SECRET_BROKER_NTFY_TOKEN", "fake-ntfy-token-3c1")
    with pytest.raises(ValueError, match="notify endpoint"):
        notifier_from_args(_notify_args(tmp_path))
    plain = "http://n.svc.example.internal:8080"  # no-raw-endpoint: allow override syntax
    monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", plain)
    with pytest.raises(ValueError, match="plaintext"):
        notifier_from_args(_notify_args(tmp_path))
    assert notifier_from_args(_notify_args(tmp_path, notify_token=None)) is not None
    secure = "https://n.svc.example.internal:8443"  # no-raw-endpoint: allow override syntax
    monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", secure)
    monkeypatch.delenv("HNX_SECRET_BROKER_NTFY_TOKEN")
    with pytest.raises(ValueError, match="HNX_SECRET_BROKER_NTFY_TOKEN is not set"):
        notifier_from_args(_notify_args(tmp_path))
    monkeypatch.setenv("HNX_SECRET_BROKER_NTFY_TOKEN", "fake-ntfy-token-3c1")
    with pytest.raises(ValueError, match="topic"):
        notifier_from_args(_notify_args(tmp_path, notify_topic="no spaces/allowed"))
    n = notifier_from_args(_notify_args(tmp_path))
    assert n.rate_limit.max_sends_all_scopes == NOTIFY_ALL_AGENTS_PER_HOUR, "a global backstop"


def test_the_notify_topic_can_stay_out_of_the_process_list(tmp_path, monkeypatch):
    from homelabnext.broker.cli import notifier_from_args

    secure = "https://n.svc.example.internal:8443"  # no-raw-endpoint: allow override syntax
    monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", secure)
    (tmp_path / "topic").write_text("hnx-ops-7f3\n")
    n = notifier_from_args(_notify_args(tmp_path, notify_topic=None, notify_token=None,
                                        notify_topic_file=str(tmp_path / "topic")))  # fmt: skip
    assert n.sender.default_topic == "hnx-ops-7f3"
    monkeypatch.setenv("HNX_BROKER_NOTIFY_TOPIC", "from-env")
    n = notifier_from_args(_notify_args(tmp_path, notify_topic=None, notify_token=None))
    assert n.sender.default_topic == "from-env"


def test_a_failed_notification_is_logged_at_most_every_few_minutes(tmp_path, caplog):
    from homelabnext.broker.service import BrokerService, load_manifest

    class Down:
        def register_pair(self, *a):
            pass

        def report(self, *a, **k):
            raise RuntimeError("ntfy down")

    manifest, docs = load_manifest(EXAMPLE)
    svc = BrokerService(tmp_path / "s", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
                        data_root=tmp_path / "d", notifier=Down(), page_timers=False)  # fmt: skip
    with caplog.at_level("WARNING", logger="homelabnext.broker.service"):
        for _ in range(3):
            svc.submit("profile:triage", "service.restart", {"grace_s": 1}, target="svc:queue")
    hits = [r for r in caplog.records if "could not be sent" in r.getMessage()]
    assert len(hits) == 1


@pytest.mark.parametrize("cmd", [["pending"], ["audit"], ["approve", "req-0000000000000000",
                                                         "--as", "sso:operator-one"]])  # fmt: skip
def test_local_commands_ignore_the_notify_topic_environment(cmd, tmp_path, monkeypatch, capsys):
    """With the topic exported beside HNX_BROKER_STATE, every local command built a notifier: with
    no endpoint each failed rc 2, and with one each could page from the CLI process."""
    monkeypatch.setenv("HNX_BROKER_NOTIFY_TOPIC", "hnx-ops")
    monkeypatch.delenv("HNX_ENDPOINT_NOTIFY", raising=False)
    rc = main([*cmd, "--manifest", str(EXAMPLE), "--state", str(tmp_path / "state")])
    err = capsys.readouterr().err
    assert "notify endpoint" not in err and rc in (0, 1), (rc, err)
