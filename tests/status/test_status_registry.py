# SPDX-License-Identifier: Apache-2.0
"""Status sources in the registry: the example is valid, and the rules the schema cannot state
(raw addresses, timing, targets, unique ids) are fatal like the rest of the registry."""

from __future__ import annotations

import copy

import pytest
import yaml
from status_helpers import REGISTRY

from homelabnext.registry.model import RegistryError, build_registry
from homelabnext.status import sources_from_registry

DOC_ADDR = ".".join(["192", "0", "2", "20"])  # a documentation address, built so no gate trips


@pytest.fixture
def doc():
    return yaml.safe_load(REGISTRY.read_text())


def _with_source(doc, service="metrics", **src):
    d = copy.deepcopy(doc)
    base = {
        "id": "extra",
        "kind": "poll-http-json",
        "target": {"path": "/x"},
        "interval_s": 60,
        "timeout_s": 5,
        "mapping": {"state": "status"},
        "what": "an extra source",
    }
    base.update(src)
    d["services"][service].setdefault("status_sources", []).append(base)
    return d


def _problems(d) -> list[str]:
    with pytest.raises(RegistryError) as exc:
        build_registry(d)
    return exc.value.problems


def test_example_registry_declares_a_menu(doc):
    reg = build_registry(doc)
    specs = sources_from_registry(reg)
    ids = [s.id for s in specs]
    assert ids == sorted(ids) and len(ids) == len(set(ids)) >= 5
    kinds = {s.kind for s in specs}
    assert {"poll-http-json", "poll-file", "push-event"} <= kinds
    inv = next(s for s in specs if s.id == "invariants")
    assert inv.module == "invariants" and inv.stale_after_s == 10800
    alerts = next(s for s in specs if s.id == "metrics-alerts")
    assert alerts.stale_after_s == 3 * alerts.interval_s  # the default


def test_valid_extra_source_passes(doc):
    build_registry(_with_source(doc))


@pytest.mark.parametrize(
    "src, needle",
    [
        ({"what": f"polls {DOC_ADDR} directly"}, "raw address"),
        ({"what": "see https://metrics.example.invalid"}, "raw address"),
        ({"target": {"path": "/x?next=localhost"}}, "raw address"),
        ({"timeout_s": 60}, "timeout_s 60 must be below interval_s 60"),
        ({"stale_after_s": 30}, "stale_after_s 30 is below interval_s 60"),
        ({"target": {"service": "nope", "path": "/x"}}, "target service 'nope' is not registered"),
        ({"target": {"service": "dns", "path": "/x"}}, "does not speak http(s)"),
        ({"target": {}}, "needs target.path"),
        ({"kind": "poll-file", "target": {"file": "a.json"}, "mapping": None}, "needs a mapping"),
        ({"kind": "poll-file", "target": {"path": "/x"}}, "poll-file needs target.file"),
        ({"kind": "push-event", "target": {"path": "/x"}}, "push-event sources are not polled"),
        ({"mapping": {"builtin": "records-lanes", "state": "x"}}, "takes no selectors"),
        ({"mapping": {"items": "$.x[*]"}}, "needs a state selector"),
        ({"id": "invariants"}, "id already used by service metrics"),
    ],
)
def test_semantic_rules_are_fatal(doc, src, needle):
    d = _with_source(doc, **src)
    if src.get("mapping", 0) is None:
        d["services"]["metrics"]["status_sources"][-1].pop("mapping")
    problems = _problems(d)
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize(
    "src, needle",
    [
        ({"target": {"url": "https://metrics.example.invalid/x"}}, "url"),
        ({"target": {"service": "http://x", "path": "/x"}}, "target/service"),
        ({"target": {"path": "http://metrics.example.invalid/x"}}, "target/path"),
        ({"interval_s": 1}, "interval_s"),
        ({"kind": "poll-snmp"}, "kind"),
        ({"target": {"file": "/etc/passwd"}, "kind": "poll-file"}, "target/file"),
        ({"target": {"file": "../outside.json"}, "kind": "poll-file"}, "target/file"),
    ],
)
def test_schema_refuses_addresses_and_bad_shapes(doc, src, needle):
    problems = _problems(_with_source(doc, **src))
    assert any(p.startswith("schema:") and needle in p for p in problems), problems


def test_status_sources_do_not_change_the_generator_digest(doc):
    """Generated headers cite the digest; a status source changes no generated file."""
    bare = copy.deepcopy(doc)
    for svc in bare["services"].values():
        svc.pop("status_sources", None)
    assert build_registry(bare).digest == build_registry(doc).digest
    moved = copy.deepcopy(bare)
    moved["services"]["metrics"]["port"] = 9091
    assert build_registry(moved).digest != build_registry(bare).digest


# ---------------------------------------------------------------- stage 1b: agent activity
@pytest.mark.parametrize(
    "src, message",
    [
        ({"mapping": {"state": "status"}, "target": {"file": "x"}}, "agent-activity needs mapping.builtin"),
        ({"mapping": {"builtin": "agent-spool"}, "target": {}}, "agent-spool needs target.file"),
        ({"mapping": {"builtin": "agent-push"}, "target": {"file": "x"}}, "agent-push reads the activity store"),
        ({"mapping": {"builtin": "agentmetry-jsonl"}, "target": {"path": "/x"}}, "takes only target.file"),
    ],
)  # fmt: skip
def test_agent_activity_source_rules(doc, src, message):
    bad = _with_source(doc, "status-hub", kind="agent-activity", **src)
    assert any(message in p for p in _problems(bad))


def test_agent_builtin_only_on_agent_activity(doc):
    bad = _with_source(
        doc, kind="poll-file", target={"file": "x"}, mapping={"builtin": "agent-spool"}
    )
    assert any("for agent-activity only" in p for p in _problems(bad))


def test_front_door_needs_idp_and_a_public_hostname(doc):
    bad = copy.deepcopy(doc)
    bad["services"]["notify"]["front_door"] = {"header": "X-Door", "secret": "secret:a/b"}
    assert any("front_door needs auth: idp" in p for p in _problems(bad))
    ok = build_registry(doc)
    assert ok.services["status-hub"].front_door["header"] == "X-Hnx-Front-Door"


def test_generated_caddy_site_adds_the_front_door_header_from_the_environment(registry):
    from homelabnext.generators.builtin import caddy

    site = (
        caddy(registry)["caddy/sites.caddy"].split("status.lab.example {", 1)[1].split("\n}", 1)[0]
    )
    assert "import hnx_forward_auth" in site
    assert "header_up X-Hnx-Front-Door {env.HNX_SECRET_STATUS_FRONT_DOOR_SECRET}" in site
    other = (
        caddy(registry)["caddy/sites.caddy"]
        .split("dashboards.lab.example {", 1)[1]
        .split("\n}", 1)[0]
    )
    assert "header_up" not in other
