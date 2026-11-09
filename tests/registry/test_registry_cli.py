# SPDX-License-Identifier: Apache-2.0
import io
from pathlib import Path

from homelabnext.registry.cli import main
from homelabnext.registry.dns import SystemDNS

EXAMPLE = str(Path(__file__).resolve().parents[2] / "examples" / "services.yml")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    rc = main(list(argv), out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


def test_validate_ok_and_bad(tmp_path):
    rc, out, _ = run("validate", EXAMPLE)
    assert rc == 0 and "21 services" in out
    bad = tmp_path / "bad.yml"
    bad.write_text("registry_version: 1\n")
    rc, _, err = run("validate", str(bad))
    assert rc == 1 and "invalid registry" in err


def test_resolve_failure_exit_1_and_message(monkeypatch):
    # the CLI uses the system resolver; answer "no such name" without a real DNS query
    monkeypatch.setattr(SystemDNS, "lookup_host", lambda self, name: [])
    rc, _, err = run("resolve", EXAMPLE, "lake-query")
    assert rc == 1 and "does not resolve" in err


def test_generate_check_roundtrip_and_drift(tmp_path):
    assert run("generate", EXAMPLE, str(tmp_path))[0] == 0
    assert run("check", EXAMPLE, str(tmp_path))[0] == 0
    (tmp_path / "hosts" / "hosts.block").write_text("tampered\n")
    rc, _, err = run("check", EXAMPLE, str(tmp_path))
    assert rc == 1 and "differs: hosts/hosts.block" in err


def test_unknown_generator_is_usage_error(tmp_path):
    rc, _, err = run("generate", EXAMPLE, str(tmp_path), "--only", "nope")
    assert rc == 2 and "unknown generator" in err


def test_list_generators_shows_eleven():
    rc, out, _ = run("list-generators")
    assert rc == 0 and len(out.split()) == 11


TIERS = str(
    Path(__file__).resolve().parents[2] / "tests/generators/fixtures/all-tiers.services.yml"
)


def test_validate_reports_the_non_primary_rows():
    rc, out, _ = run("validate", TIERS)
    assert rc == 0 and out.startswith("ok: 6 services, 4 non-primary, 9 hosts, sha256:")
    assert "21 services, 0 non-primary, " in run("validate", EXAMPLE)[1]


def test_resolve_row_by_its_row_name(monkeypatch):
    monkeypatch.setattr(
        SystemDNS,
        "lookup_host",
        lambda self, name: [name] if "candidate" in name else [],
    )
    rc, out, _ = run("resolve", TIERS, "hub-candidate", "--row")
    assert rc == 0 and out == "https://hub-candidate.svc.example.internal:" + "8443\n"
    rc, _, err = run("resolve", TIERS, "hub-candidate")
    assert rc == 1 and "'hub-candidate': is an eval row, not a capability" in err
    assert "use --row" in err or "(--row)" in err
    rc, _, err = run("resolve", TIERS, "hub-oldlab", "--row")
    assert rc == 1 and "legacy row answers by no name" in err


def test_a_generator_refusing_the_registry_exits_1_with_its_reason(tmp_path):
    minimal = str(Path(EXAMPLE).parent / "minimal" / "services.yml")
    rc, _, err = run("generate", minimal, str(tmp_path), "--only", "idp_realm")
    assert rc == 1 and "no primary or eval idp row has impl 'keycloak'" in err
    assert not any(tmp_path.iterdir())


EXAMPLES = [*sorted(Path(EXAMPLE).parent.glob("*/services.yml")), Path(EXAMPLE)]


def test_generate_succeeds_over_every_example_registry(tmp_path):
    """A lab whose IdP is not the realm format's product renders everything but the realm."""
    for i, path in enumerate(EXAMPLES):
        rc, _, err = run("generate", str(path), str(tmp_path / str(i)))
        assert rc == 0, (path, err)
        assert run("check", str(path), str(tmp_path / str(i)))[0] == 0, path


def test_a_full_generate_prunes_a_stale_realm(tmp_path):
    minimal = str(Path(EXAMPLE).parent / "minimal" / "services.yml")
    assert run("generate", EXAMPLE, str(tmp_path))[0] == 0
    assert (tmp_path / "idp" / "realm.json").is_file()
    rc, _, _ = run("generate", minimal, str(tmp_path))
    assert rc == 0 and not (tmp_path / "idp" / "realm.json").exists()


# ---- hnx registry standing (ADR-0039 decision 8, checklist X-12) -----------------------------


def test_standing_lists_every_non_primary_row_with_its_days_left():
    rc, out, _ = run("standing", TIERS, "--today", "2026-12-01")
    assert rc == 0
    assert out.splitlines() == [
        "hub-candidate: eval status-hub until 2026-12-31 (30 day(s) left): the next hub release in "
        "shadow",
        "hub-oldlab: legacy status-hub until 2027-01-31 (61 day(s) left): the old lab's dashboard, "
        "until its ledger row closes",
        "hub-rollback: retiring status-hub until 2026-12-15 (14 day(s) left): the former hub in its "
        "rollback window",
        "kc-trial: eval idp until 2026-12-31 (30 day(s) left): the single sign-on candidate",
    ]


def test_standing_overdue_fails_only_past_the_date():
    rc, out, _ = run("standing", TIERS, "--overdue", "--today", "2026-12-15")
    assert rc == 0 and out == "ok: no non-primary row past its until (4 non-primary)\n"
    rc, out, err = run("standing", TIERS, "--overdue", "--today", "2026-12-16")
    assert rc == 1
    assert out.startswith(
        "hub-rollback: retiring status-hub until 2026-12-15 (overdue by 1 day(s))"
    )
    assert "1 non-primary row(s) past their until on 2026-12-16" in err


def test_standing_the_example_registry_is_green_and_json_reads_back(monkeypatch):
    import json

    monkeypatch.setenv("HNX_TODAY", "2026-11-08")
    assert run("standing", EXAMPLE, "--overdue")[0] == 0
    rc, out, _ = run("standing", TIERS, "--overdue", "--json", "--today", "2027-02-01")
    body = json.loads(out)
    assert rc == 1 and body["today"] == "2027-02-01"
    assert [r["row"] for r in body["rows"]] == [
        "hub-candidate",
        "hub-oldlab",
        "hub-rollback",
        "kc-trial",
    ]
    assert all(r["overdue"] and r["days_left"] < 0 for r in body["rows"])


def test_standing_refuses_a_bad_date(monkeypatch):
    assert run("standing", EXAMPLE, "--today", "soon")[0] == 2
    monkeypatch.setenv("HNX_TODAY", "soon")
    rc, _, err = run("standing", EXAMPLE)
    assert rc == 2 and "HNX_TODAY='soon'" in err


def test_standing_reports_an_until_that_is_no_date_as_invalid_not_overdue():
    """The registry refuses such a row before this runs; a reader handed one anyway says what it
    is instead of counting it a day overdue."""
    from homelabnext.registry.standing import Standing, text

    r = Standing("trial", "dns", "eval", "2026-02-30", "a candidate", 0, valid=False)
    assert r.overdue and r.to_dict()["valid"] is False
    assert (
        text([r])
        == "trial: eval dns until 2026-02-30 (invalid until: no calendar date): a candidate\n"
    )
