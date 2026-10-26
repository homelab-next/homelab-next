# SPDX-License-Identifier: Apache-2.0
"""One pass and one fail per lint rule."""

from __future__ import annotations

from datetime import date

import pytest
from cust_helpers import TODAY, load_one, make_doc, write_custom

from homelabnext.customization import lint


def codes(findings):
    return {f.code for f in findings}


def run(tmp_path, uni, docs, today=TODAY, enabled=None):
    for i, (doc, files) in enumerate(docs):
        write_custom(tmp_path, f"c{i}", doc, files)
    return lint(load_one(tmp_path), uni, today, enabled)


def test_clean_customization_has_no_findings(tmp_path, uni):
    assert run(tmp_path, uni, [(make_doc(), None)]) == []


def test_cu001_schema(tmp_path, uni):
    f = run(tmp_path, uni, [(make_doc(owner=None), None)])
    assert "CU001" in codes(f) and any("owner" in x.message for x in f)


def test_cu002_duplicate_id(tmp_path, uni):
    f = run(tmp_path, uni, [(make_doc(), None), (make_doc(), None)])
    assert "CU002" in codes(f)


def _addr(*octets):
    """Built at run time so this file itself contains no endpoint literal."""
    return ".".join(str(o) for o in octets)


@pytest.mark.parametrize(
    "value",
    [f"http://{_addr(192, 0, 2, 10)}:8080/x", _addr(10, 1, 2, 3), "host.example" + ".internal:443"],
)
def test_cu003_raw_endpoint_in_document(tmp_path, uni, value):
    doc = make_doc(
        action={"role": "example_service", "vars": {"example_service_health_path": value}}
    )
    assert "CU003" in codes(run(tmp_path, uni, [(doc, None)]))


def test_cu003_raw_endpoint_in_referenced_file(tmp_path, uni):
    doc = make_doc(
        kind="hook",
        action={
            "role": "example_service",
            "entry_point": "health",
            "phase": "post",
            "tasks_file": "t.yml",
        },
    )
    f = run(
        tmp_path,
        uni,
        [
            (
                doc,
                {"t.yml": f"- ansible.builtin.uri: {{url: 'http://{_addr(127, 0, 0, 1)}:8080/x'}}"},
            )
        ],
    )
    assert "CU003" in codes(f)


def test_cu004_unknown_role_template_variable_service(tmp_path, uni):
    def one(doc, files=None):
        d = tmp_path / str(len(list(tmp_path.iterdir())))
        d.mkdir()
        write_custom(d, "c", doc, files)
        return lint(load_one(d), uni, TODAY)

    assert "CU004" in codes(one(make_doc(action={"role": "nope", "vars": {"nope_x": 1}})))
    assert "CU004" in codes(
        one(make_doc(action={"role": "example_service", "vars": {"example_service_unknown": 1}}))
    )
    assert "CU004" in codes(
        one(make_doc(action={"role": "example_service", "vars": {"compose_app_x": 1}}))
    )
    over = make_doc(
        kind="patch-overlay",
        action={
            "role": "example_service",
            "template": "missing.j2",
            "overlay": "o.j2",
            "mode": "append",
        },
    )
    assert "CU004" in codes(one(over, {"o.j2": "x"}))
    reg = make_doc(kind="registry-patch", action={"service": "no-such", "set": {"tls": "none"}})
    assert "CU004" in codes(one(reg))
    struct = make_doc(kind="registry-patch", action={"service": "edge-proxy", "set": {"host": "x"}})
    assert "CU004" in codes(one(struct))


@pytest.mark.parametrize(
    "scope",
    [
        {"capabilities": ["cap:no-such-capability"]},
        {"services": ["svc:no-such-service"]},
        {"roles": ["no_such_role"]},
        {"hosts": ["no-such-host"]},
    ],
)
def test_cu005_unresolved_scope(tmp_path, uni, scope):
    assert "CU005" in codes(run(tmp_path, uni, [(make_doc(scope=scope), None)]))


def test_cu005_resolving_scope_passes(tmp_path, uni):
    scope = {
        "capabilities": ["cap:edge"],
        "services": ["svc:edge-proxy"],
        "roles": ["example_service"],
        "hosts": ["edge-core"],
    }
    assert run(tmp_path, uni, [(make_doc(scope=scope), None)]) == []


@pytest.mark.parametrize("rel", ["missing.yml", "sub/../../escape.yml"])
def test_cu006_missing_or_escaping_file(tmp_path, uni, rel):
    doc = make_doc(
        kind="hook",
        action={
            "role": "example_service",
            "entry_point": "main",
            "phase": "pre",
            "tasks_file": rel,
        },
    )
    f = run(tmp_path, uni, [(doc, None)])
    assert codes(f) & {"CU006", "CU001"}


def test_cu006_symlink_escape_and_core(tmp_path, uni, repo_root):
    import os

    outside = tmp_path / "outside.yml"
    outside.write_text("- name: x\n")
    ov = tmp_path / "ov"
    d = write_custom(
        ov,
        "c",
        make_doc(
            kind="hook",
            action={
                "role": "example_service",
                "entry_point": "main",
                "phase": "pre",
                "tasks_file": "t.yml",
            },
        ),
    )
    os.symlink(outside, d.parent / "t.yml")
    assert "CU006" in codes(lint(load_one(ov), uni, TODAY))
    ov2 = tmp_path / "ov2"
    d2 = write_custom(
        ov2,
        "c",
        make_doc(
            kind="hook",
            action={
                "role": "example_service",
                "entry_point": "main",
                "phase": "pre",
                "tasks_file": "core.yml",
            },
        ),
    )
    os.symlink(repo_root / "ansible/roles/example_service/tasks/main.yml", d2.parent / "core.yml")
    f = lint(load_one(ov2), uni, TODAY)
    assert any(x.code == "CU006" for x in f)


def test_cu007_dates(tmp_path, uni):
    assert "CU007" in codes(run(tmp_path, uni, [(make_doc(review_by="2026-02-30"), None)]))
    sub = tmp_path / "b"
    assert "CU007" in codes(run(sub, uni, [(make_doc(review_by="2026-08-01"), None)]))
    sub = tmp_path / "c"
    far = make_doc(created="2026-09-01", review_by="2030-01-01")
    assert "CU007" in codes(run(sub, uni, [(far, None)]))


def test_cu008_cu009_expiry(tmp_path, uni):
    f = run(tmp_path, uni, [(make_doc(review_by="2026-12-01"), None)], today=date(2026, 12, 2))
    assert "CU008" in codes(f)
    f = run(
        tmp_path / "w", uni, [(make_doc(review_by="2026-12-01"), None)], today=date(2026, 11, 25)
    )
    assert codes(f) == {"CU009"} and f[0].severity == "warning"
    f = run(
        tmp_path / "ok", uni, [(make_doc(review_by="2026-12-01"), None)], today=date(2026, 12, 1)
    )
    assert "CU008" not in codes(f)  # the review date itself is still in date


def test_cu010_contract(tmp_path, uni):
    for bad in [
        "cap:no-such",
        "adr:no-such-adr",
        "https://schemas.example.internal/homelabnext/platform/ghost/1.0",
    ]:
        sub = tmp_path / bad.replace(":", "_").replace("/", "_")
        assert "CU010" in codes(run(sub, uni, [(make_doc(contract=bad), None)])), bad
    for good in [
        "adr:hypervisor-is-not-modular",
        "https://schemas.example.internal/homelabnext/platform/capability/1.1",
    ]:
        sub = tmp_path / f"good{len(good)}"
        assert "CU010" not in codes(run(sub, uni, [(make_doc(contract=good), None)]))


def test_cu011_conflict_same_variable_overlapping_scope(tmp_path, uni):
    a = make_doc(
        id="custom:one",
        action={"role": "example_service", "vars": {"example_service_listen_port": 1}},
    )
    b = make_doc(
        id="custom:two",
        action={"role": "example_service", "vars": {"example_service_listen_port": 2}},
    )
    assert "CU011" in codes(run(tmp_path, uni, [(a, None), (b, None)]))


def test_no_conflict_when_scopes_are_disjoint_hosts(tmp_path, uni):
    act = {"role": "example_service", "vars": {"example_service_listen_port": 1}}
    a = make_doc(id="custom:one", scope={"hosts": ["dns-core"]}, action=act)
    b = make_doc(id="custom:two", scope={"hosts": ["mon-core"]}, action=act)
    assert "CU011" not in codes(run(tmp_path, uni, [(a, None), (b, None)]))


def test_cu013_enablement(tmp_path, uni):
    opt = make_doc(optional=True)
    f = run(
        tmp_path,
        uni,
        [(opt, None)],
        enabled={"custom:test-port": ["no-such-host"], "custom:ghost": []},
    )
    assert [x.code for x in f if x.code == "CU013"] == ["CU013", "CU013"]
    f = run(tmp_path / "n", uni, [(make_doc(), None)], enabled={"custom:test-port": []})
    assert any("not optional" in x.message for x in f)


def test_cu014_upstream_accepted_warns(tmp_path, uni):
    f = run(tmp_path, uni, [(make_doc(upstream="accepted"), None)])
    assert codes(f) == {"CU014"} and f[0].severity == "warning"


def test_optional_inactive_scope_not_checked_until_enabled(tmp_path, uni):
    doc = make_doc(optional=True, scope={"capabilities": ["cap:hypervisor"]})
    assert run(tmp_path, uni, [(doc, None)]) == []
    f = run(tmp_path / "e", uni, [(doc, None)], enabled={"custom:test-port": ["edge-core"]})
    assert "CU005" in codes(f)
