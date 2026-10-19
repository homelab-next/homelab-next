# SPDX-License-Identifier: Apache-2.0
"""F-15: every deploy emits a what-changed event, built from the changelog section it ships."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from homelabnext.events import (
    EventError,
    FakeForwarder,
    FakeForwarderServer,
    Publisher,
    validate_event,
)
from homelabnext.events.cli import main
from homelabnext.events.deploy import (
    EVENT_TYPE,
    ChangelogError,
    changes_from_changelog,
    deploy_changed_event,
    emit_deploy_changed,
)
from homelabnext.state import StateStore

REPO = Path(__file__).resolve().parents[2]
T = "2026-01-01T00:00:00Z"
CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Not released yet.

## [0.2.0] - 2026-01-01

### Added

- Enrichment of event envelopes
  with asset owner and criticality.
- A second addition.

### Fixed

- Publisher resends a lost acknowledgement.

## [0.1.0] - 2025-12-01

### Added

- First release.
"""


def test_changes_come_from_the_version_section():
    assert changes_from_changelog(CHANGELOG, "0.2.0") == [
        {
            "kind": "added",
            "summary": "Enrichment of event envelopes with asset owner and criticality.",
        },
        {"kind": "added", "summary": "A second addition."},
        {"kind": "fixed", "summary": "Publisher resends a lost acknowledgement."},
    ]
    assert changes_from_changelog(CHANGELOG, "0.1.0") == [
        {"kind": "added", "summary": "First release."}
    ]


@pytest.mark.parametrize(
    "text, version",
    [
        (CHANGELOG, "9.9.9"),  # no section: the deploy is refused
        ("## [1.0.0]\n\nnothing listed\n", "1.0.0"),  # empty section
        ("## [1.0.0]\n\n### Improved\n\n- x\n", "1.0.0"),  # not a Keep a Changelog heading
    ],
)
def test_changelog_problems_refuse_the_event(text, version):
    with pytest.raises(ChangelogError):
        changes_from_changelog(text, version)


def test_long_summaries_are_clipped():
    text = "## [1.0.0]\n\n### Changed\n\n- " + "word " * 300 + "\n"
    (c,) = changes_from_changelog(text, "1.0.0")
    assert len(c["summary"]) == 500
    assert c["summary"].endswith("...")


def _event(**kw):
    args = {
        "component": "svc:lake-query",
        "to_version": "0.2.0",
        "from_version": "0.1.0",
        "changes": changes_from_changelog(CHANGELOG, "0.2.0"),
        "source": "svc:release-pipeline",
        "environment": "lab",
        "time": T,
    }
    args.update(kw)
    return deploy_changed_event(**args)


def test_event_is_valid_and_its_id_is_the_deploy_identity():
    ev = _event()
    validate_event(ev)
    assert ev["type"] == EVENT_TYPE
    assert ev["subject"] == "svc:lake-query"
    assert ev["data"]["deploy_id"] == "svc-lake-query-0.2.0-lab"
    assert _event()["id"] == ev["id"]  # a retried deploy step: same id
    assert _event(environment="prod")["id"] != ev["id"]
    with pytest.raises(EventError):
        _event(changes=[])  # a deploy that changed nothing is not a what-changed event
    with pytest.raises(EventError):
        _event(component="https://pkg.example.internal/x")


def test_emit_publishes_once(tmp_path):
    fwd = FakeForwarder()
    pub = Publisher(fwd, StateStore(tmp_path / "s.json"), sleep=lambda s: None)
    ev, res = emit_deploy_changed(pub, **{"component": "pkg:homelabnext", "to_version": "0.2.0",
                                          "changes": [{"kind": "added", "summary": "x"}],
                                          "source": "svc:release-pipeline", "time": T})  # fmt: skip
    assert res.status == "sent"
    assert fwd.ids == [ev["id"]]
    _, again = emit_deploy_changed(pub, **{"component": "pkg:homelabnext", "to_version": "0.2.0",
                                           "changes": [{"kind": "added", "summary": "x"}],
                                           "source": "svc:release-pipeline", "time": T})  # fmt: skip
    assert again.status == "duplicate"
    assert fwd.ids == [ev["id"]]


def test_cli_writes_and_publishes(tmp_path, capsys):
    cl = tmp_path / "CHANGELOG.md"
    cl.write_text(CHANGELOG)
    out = tmp_path / "out" / "deploy.json"
    with FakeForwarderServer() as srv:
        rc = main(
            ["deploy-changed", "--component", "pkg:homelabnext", "--to", "0.2.0", "--from",
             "0.1.0", "--changelog", str(cl), "--source", "svc:release-pipeline", "--time", T,
             "--out", str(out), "--forwarder", srv.url, "--state", str(tmp_path / "st.json")]
        )  # fmt: skip
        assert rc == 0
        ev = json.loads(out.read_text())
        validate_event(ev)
        assert srv.fake.ids == [ev["id"]]
    assert len(ev["data"]["changes"]) == 3
    assert "changelog" not in ev["data"]  # an absolute path is not recorded


def test_cli_refuses_a_version_without_a_section(tmp_path, capsys):
    cl = tmp_path / "CHANGELOG.md"
    cl.write_text(CHANGELOG)
    rc = main(["deploy-changed", "--component", "pkg:homelabnext", "--to", "3.0.0",
               "--changelog", str(cl), "--source", "svc:release-pipeline", "--time", T])  # fmt: skip
    assert rc == 1
    assert "no '## [3.0.0]' section" in capsys.readouterr().err


def test_repo_changelog_yields_an_event_for_the_current_version(capsys):
    from homelabnext import __version__

    rc = main(["deploy-changed", "--component", "pkg:homelabnext", "--to", __version__,
               "--changelog", str(REPO / "CHANGELOG.md"), "--source", "svc:release-pipeline",
               "--time", T])  # fmt: skip
    assert rc == 0
    validate_event(json.loads(capsys.readouterr().out))


def test_the_release_workflow_emits_the_event():
    """The deploy path of the package is the release workflow: it must build the event."""
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())
    steps = wf["jobs"]["build"]["steps"]
    runs = [s.get("run", "") for s in steps]
    emit = [i for i, r in enumerate(runs) if "events deploy-changed" in r]
    assert emit, "release.yml build job does not emit the deploy.changed event"
    checksums = next(i for i, s in enumerate(steps) if s.get("name") == "checksums")
    assert emit[0] < checksums  # the event is checksummed and attached with the SBOM
    release = " ".join(s.get("run", "") for s in wf["jobs"]["github-release"]["steps"])
    assert "deploy-changed.json" in release
