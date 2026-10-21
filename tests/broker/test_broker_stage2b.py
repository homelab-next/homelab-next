# SPDX-License-Identifier: Apache-2.0
"""Broker stage 2b: the Approvals-page link on ``decision.requested`` and the vault migration
(``hnx broker import-proposals``).  The hub page itself is tested in
``tests/status/test_approvals.py``."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from conformance.protocols.broker import BrokerError
from homelabnext.broker import importer
from homelabnext.broker.cli import main
from homelabnext.broker.service import BrokerService, check_approvals_url
from homelabnext.events.envelope import event_problems
from homelabnext.notify.core import Message, Notifier
from homelabnext.notify.senders import NtfySender
from homelabnext.records.notes import parse_note, validate_note

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"
VAULT = Path(__file__).resolve().parent / "fixtures" / "vault-proposals"
AGENT = "profile:triage"
URL = "https://status.lab.example/approvals"


def _notifier(sent):
    class Sender:
        def send(self, message):
            sent.append(message)

    class Store(dict):
        def put(self, k, v):
            self[k] = v

    return Notifier(sender=Sender(), store=Store(), clock=lambda: 0.0)


def _svc(tmp_path, **kw) -> BrokerService:
    return BrokerService.from_manifest(
        EXAMPLE, tmp_path / "state", data_root=tmp_path / "data", **kw
    )


# -- the notification link ----------------------------------------------------------------------


def test_decision_requested_links_the_approvals_page_when_configured(tmp_path):
    sent = []
    svc = _svc(tmp_path, notifier=_notifier(sent), approvals_url=URL)
    rid = svc.submit(AGENT, "service.restart", {"grace_s": 5}, target="svc:queue")
    [ev] = svc.state.outbox()
    link = f"{URL}?request={rid}"
    assert ev["data"]["link"] == link and event_problems(ev) == []
    assert sent[0].click == link and sent[0].body.endswith(f"Review: {link}")
    req = NtfySender(endpoint="https://ntfy.lab.example", default_topic="hnx").build_request(
        sent[0]
    )
    assert req.get_header("Click") == link


def test_no_link_without_a_configured_url(tmp_path):
    sent = []
    svc = _svc(tmp_path, notifier=_notifier(sent))
    svc.submit(AGENT, "service.restart", {"grace_s": 5}, target="svc:queue")
    [ev] = svc.state.outbox()
    assert "link" not in ev["data"] and sent[0].click is None and "Review" not in sent[0].body


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://status.lab.example/approvals",
        "https://user:fake-pass" + "@" + "status.lab.example/approvals",  # credentials
        "https://status.lab.example/approvals?x=1",
        "https://status.lab.example/approvals#top",
        "/approvals",
        "https://status.lab.example/a pprovals",
    ],
)
def test_an_approvals_url_that_is_not_a_page_url_is_refused(bad):
    with pytest.raises(ValueError):
        check_approvals_url(bad)
    assert check_approvals_url(URL) == URL and check_approvals_url(None) is None


def test_a_click_link_must_be_http():
    with pytest.raises(ValueError):
        Message(key="k", title="t", body="b", click="javascript:alert(1)")


def test_the_cli_passes_the_approvals_url(tmp_path, capsys):
    state = tmp_path / "state"
    args = ["--manifest", str(EXAMPLE), "--state", str(state), "--approvals-url", URL]
    assert (
        main(["submit", "service.restart", "--as", AGENT, "--params", '{"grace_s": 5}', *args]) == 0
    )
    [ev] = BrokerService.from_manifest(EXAMPLE, state).state.outbox()
    assert ev["data"]["link"].startswith(URL + "?request=")
    bad = ["--manifest", str(EXAMPLE), "--state", str(state), "--approvals-url", "ftp://x/y"]
    assert main(["pending", *bad]) == 2


# -- the vault migration ------------------------------------------------------------------------


def _by_source(rows):
    return {r.source: r for r in rows}


def test_import_dry_run_maps_generically_and_reports_what_it_cannot():
    rows = _by_source(importer.read_dir(VAULT))
    a = rows["2026-03-02-queue-bot-raise-drain-timeout.md"]
    assert a.outcome == "mapped" and a.params["slug"] == "queue-bot-raise-drain-timeout"
    note = a.params["note"]
    assert (note["title"], note["risk"], note["created"]) == (
        "Raise the queue drain timeout",
        "medium",
        "2026-03-02T00:00:00Z",
    )
    assert "requesting_agent" not in note and "status" not in note
    assert "requested-by:queue-bot" in note["provenance"]["inputs"]
    assert a.unmapped == ["labels"] and note["affects"] == ["svc:queue"]
    b = rows["2026-03-03-log-bot-rotate-audit-logs.md"]  # the other spellings
    assert (b.params["note"]["title"], b.params["note"]["risk"]) == (
        "Rotate the audit logs weekly",
        "low",
    )
    assert b.params["note"]["rollback"] == "restore the previous logrotate file"
    assert rows["2026-03-04-log-bot-no-rollback.md"].outcome == "unmappable"
    assert "rollback" in rows["2026-03-04-log-bot-no-rollback.md"].problem
    assert rows["2026-03-05-queue-bot-done.md"].outcome == "skipped"
    assert rows["notes-without-frontmatter.md"].outcome == "unmappable"
    # a default fills the gap, and says so
    c = _by_source(importer.read_dir(VAULT, default_rollback="revert it"))[
        "2026-03-04-log-bot-no-rollback.md"
    ]
    assert c.outcome == "mapped" and "rollback defaulted" in c.notes


def test_import_keeps_invalid_lists_out_and_never_names_the_requester():
    text = (
        "---\ntitle: Widen the window\nrisk: low\nrollback: narrow it\n"
        "requesting_agent: profile:someone-else\naffects: [not a logical id]\n---\nbody\n"
    )
    m = importer.map_proposal("2026-01-02-widen.md", text)
    assert m.outcome == "mapped" and "affects" not in m.params["note"]
    assert m.unmapped and m.unmapped[0].startswith("affects (invalid")
    validate_note({**m.params["note"], "requesting_agent": "profile:importer"})
    assert "requesting_agent" not in m.params["note"]


def _cli(tmp_path, *extra) -> list[str]:
    return [
        "import-proposals",
        str(VAULT),
        "--manifest",
        str(EXAMPLE),
        "--state",
        str(tmp_path / "state"),
        "--data-root",
        str(tmp_path / "data"),
        "--json",
        *extra,
    ]


def test_import_dry_run_writes_nothing_and_apply_files_through_the_broker(tmp_path, capsys):
    inbox = tmp_path / "data" / "records" / "inbox"
    assert main(_cli(tmp_path)) == 1  # two files cannot be imported: say so in the exit code
    dry = json.loads(capsys.readouterr().out)
    assert dry["apply"] is False and not inbox.exists()
    assert not (tmp_path / "state").exists(), "a dry run does not touch the broker"

    assert main(_cli(tmp_path, "--apply", "--as", AGENT)) == 1
    out = {f["source"]: f for f in json.loads(capsys.readouterr().out)["files"]}
    assert out["2026-03-02-queue-bot-raise-drain-timeout.md"]["outcome"] == "filed"
    names = sorted(p.name for p in inbox.iterdir())
    assert names == [
        "2026-03-02-triage-queue-bot-raise-drain-timeout.md",
        "2026-03-03-triage-log-bot-rotate-audit-logs.md",
    ]
    fm, body = parse_note((inbox / names[0]).read_text())
    assert fm["requesting_agent"] == AGENT and fm["provenance"]["source"] == AGENT
    assert body.strip() == "The queue drained slowly twice this week."
    svc = BrokerService.from_manifest(EXAMPLE, tmp_path / "state")
    filed = svc.audit_documents(action="proposal.file", outcome="ok", operation="call")
    assert len(filed) == 2, "each one is an audited broker call"

    # idempotent: a second apply adds nothing
    main(_cli(tmp_path, "--apply", "--as", AGENT))
    again = {f["source"]: f for f in json.loads(capsys.readouterr().out)["files"]}
    assert again["2026-03-02-queue-bot-raise-drain-timeout.md"]["outcome"] == "exists"
    assert sorted(p.name for p in inbox.iterdir()) == names


def test_import_apply_needs_an_authenticated_caller(tmp_path, capsys):
    prod = tmp_path / "broker"
    shutil.copytree(EXAMPLE.parent, prod)
    doc = yaml.safe_load(EXAMPLE.read_text())
    doc["dev_identity"] = False
    (prod / "manifest.yml").write_text(yaml.safe_dump(doc))
    args = _cli(tmp_path, "--apply", "--as", AGENT)
    args[args.index(str(EXAMPLE))] = str(prod / "manifest.yml")
    assert main(args) == 1
    assert "dev-identity-disabled" in capsys.readouterr().err
    assert not (tmp_path / "data" / "records").exists()


# -- review regressions: two agents, one name ------------------------------------------------


def _proposal(agent: str) -> str:
    return f"---\ntitle: Fix x\nrisk: low\nrollback: undo\nrequesting_agent: {agent}\n---\nbody\n"


def test_same_named_proposals_from_two_agents_get_two_files(tmp_path):
    (tmp_path / "2026-09-04-agent-a-fix-x.md").write_text(_proposal("agent-a"))
    (tmp_path / "2026-09-04-agent-b-fix-x.md").write_text(_proposal("agent-b"))
    rows = importer.read_dir(tmp_path)
    assert [r.params["slug"] for r in rows] == ["agent-a-fix-x", "agent-b-fix-x"]
    filed: set[str] = set()

    def call(params):
        key = (params["note"]["created"], params["slug"])
        if key in filed:
            err = BrokerError("exists")
            err.reason = "lane-exists"
            raise err
        filed.add(key)
        return {"path": "/".join(key)}

    assert [r.outcome for r in importer.apply(rows, call, "profile:importer")] == ["filed"] * 2


def test_two_sources_mapping_to_one_name_are_a_conflict(tmp_path):
    text = "---\ntitle: Same title\nrisk: low\nrollback: undo\ncreated: 2026-09-04\n---\n"
    (tmp_path / "a.md").write_text(text)
    (tmp_path / "b.md").write_text(text.replace("undo", "undo it"))
    rows = importer.apply(importer.read_dir(tmp_path), lambda p: {"path": "x"}, "profile:i")
    assert [r.outcome for r in rows] == ["filed", "conflict"]
    assert "a.md" in rows[1].problem
