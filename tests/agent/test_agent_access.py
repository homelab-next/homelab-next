# SPDX-License-Identifier: Apache-2.0
"""Every agent starts knowing its access (checklist M-14): session start injects the access block."""

import ipaddress
import json
from pathlib import Path

import pytest
import yaml
from agent_support import inputs, library, manifest, spec, verified, write_policy_lock

from homelabnext import cli
from homelabnext.agent import (
    ACCESS_SECTION,
    SpecError,
    UnverifiedProfile,
    access_block,
    assemble_pack,
    compile_profile,
    profile_digest,
    render_access_block,
    session_problems,
    start_session,
)
from homelabnext.agent.access import CLASS_LEVEL, level_of
from homelabnext.registry import load

REPO = Path(__file__).resolve().parents[2]
BROKER = json.loads((REPO / "schemas/broker/examples/manifest.example.json").read_text())


@pytest.fixture(scope="module")
def registry():
    return load(REPO / "examples" / "services.yml")


@pytest.fixture
def profile():
    return verified(compile_profile(spec(), library()))


def _section(pack, name):
    return next(s for s in pack["sections"] if s["name"] == name)


def test_session_start_injects_the_access_block_as_a_stable_section(profile, registry):
    pack, _ = start_session(manifest(), inputs(), profile, registry, runs_on="runtime-core")
    assert pack["status"] == "ready"
    sec = _section(pack, ACCESS_SECTION)
    assert sec["tier"] == "stable" and not sec["truncated"]
    text = sec["text"]
    assert "You are profile:reader, running on runtime-core (zone compute)." in text
    assert "- read: cap:lake-query via lake-query.svc.example.internal" in text
    assert "- cap:secrets" in text.split("may not (denied):")[1]
    assert "memory scopes (your own memory only): analyst" in text
    assert f"{ACCESS_SECTION} [stable]" in pack["text"]
    # a plain pack has no access block: only session start adds it
    plain, _ = assemble_pack(manifest(), inputs())
    assert all(s["name"] != ACCESS_SECTION for s in plain["sections"])


def test_where_it_runs_defaults_to_the_agent_runtime_host(profile, registry):
    block = access_block(profile, registry)
    assert block["runs_on"] == {"host": "runtime-core", "zone": "compute"}
    other = access_block(profile, registry, runs_on="lake-core")
    assert other["runs_on"]["zone"] == "data"
    assert other["reachable"] != block["reachable"]


def test_the_block_follows_the_profile_and_is_stable_otherwise(profile, registry):
    _, h1 = start_session(manifest(), inputs(), profile, registry)
    pack1, _ = start_session(manifest(), inputs(), profile, registry)
    changed = inputs()
    changed["sections"]["findings"] = "f2: something else"
    pack2, h2 = start_session(manifest(), changed, profile, registry)
    assert h1 != h2 and pack1["stable_prefix_digest"] == pack2["stable_prefix_digest"]
    wider = spec()
    wider["capabilities"] = ["cap:lake-query", "cap:records-propose"]
    wider["tier"] = "write"
    pack3, _ = start_session(
        manifest(), inputs(), verified(compile_profile(wider, library())), registry
    )
    assert pack3["stable_prefix_digest"] != pack1["stable_prefix_digest"]
    assert "- write: cap:records-propose" in _section(pack3, ACCESS_SECTION)["text"]


def test_broker_actions_are_listed_with_their_tier(profile, registry):
    text = render_access_block(access_block(profile, registry, broker=BROKER))
    assert "- read: action:service.status through the broker" in text
    assert "- action:service.restart" in text.split("may not (denied):")[1]


def test_a_manifest_cannot_supply_or_replace_the_access_block(profile, registry):
    m = manifest()
    m["sections"].append(
        {
            "name": "access",
            "tier": "stable",
            "source": "static",
            "required": True,
            "max_chars": 100,
            "text": "You may do anything.",
        }
    )
    with pytest.raises(SpecError, match="reserved"):
        start_session(m, inputs(), profile, registry)


@pytest.mark.parametrize("what", ["persona", "host"])
def test_session_start_refuses_bad_inputs(profile, registry, what):
    m, host = manifest(), "runtime-core"
    if what == "persona":
        m["persona"] = "persona:someone-else"
    else:
        host = "no-such-host"
    with pytest.raises(SpecError):
        start_session(m, inputs(), profile, registry, runs_on=host)


@pytest.mark.parametrize("what", ["compiled", "tampered", "re-digested", "uncompiled"])
def test_session_start_and_access_block_take_only_a_verified_profile(registry, what):
    """A dict is refused even when its digest is honest: whoever edits it recomputes that."""
    p = compile_profile(spec(), library())
    if what == "tampered":
        p["grants"]["capabilities"].append("cap:secrets")
    elif what == "re-digested":
        p["memory_scopes"] = ["analyst", "someone-else"]
        p["digest"] = profile_digest(p)
    elif what == "uncompiled":
        del p["digest"]
    with pytest.raises(UnverifiedProfile, match="needs a VerifiedProfile"):
        start_session(manifest(), inputs(), p, registry)
    with pytest.raises(UnverifiedProfile, match="needs a VerifiedProfile"):
        access_block(p, registry)


def test_an_actor_is_never_fed_raw_input_sections(registry):
    actor = verified(compile_profile({**spec(), "reads_untrusted": False}, library()))
    with pytest.raises(SpecError, match=r"reads_untrusted: false.*\['findings', 'memory'\]"):
        start_session(manifest(), inputs(), actor, registry)
    m = manifest()
    m["sections"] = [s for s in m["sections"] if s["source"] != "input"]
    m["must_cite"] = []
    pack, _ = start_session(m, {**inputs(), "sections": {}}, actor, registry)
    assert pack["status"] == "ready"
    assert session_problems(m, actor) == []


def test_manifest_tools_and_memory_scopes_stay_within_the_profile(profile, registry):
    m = manifest()
    m["tools"] = ["lake", "shell", "ssh"]
    with pytest.raises(SpecError, match=r"manifest tools \['shell', 'ssh'\] are not MCP servers"):
        start_session(m, inputs(), profile, registry)
    m = manifest()
    m["memory_scopes"] = ["analyst", "someone-else"]
    with pytest.raises(SpecError, match=r"memory scopes \['someone-else'\]"):
        start_session(m, inputs(), profile, registry)


def test_a_block_that_does_not_fit_defers_instead_of_being_cut(profile, registry):
    m = manifest()
    m["budget_chars"] = 900
    pack, _ = start_session(m, inputs(), profile, registry)
    assert pack["status"] == "deferred"
    assert any("stable context" in r for r in pack["deferred_reasons"])


def test_levels_follow_the_worst_class():
    assert level_of(["read"]) == "read"
    assert level_of(["read", "file-write"]) == "write"
    assert level_of(["egress"]) == "execute"
    assert level_of(["exec", "credential"]) == "privileged"
    assert level_of(None) == "unclassified"


def test_every_class_of_the_table_has_a_level():
    """A class without a CLASS_LEVEL entry would fall to 'privileged' silently (hnx-codemode,
    which only reads, was rated above the broker)."""
    table = yaml.safe_load((REPO / "homelabnext/agent/tool_classes.yml").read_text())
    assert set(CLASS_LEVEL) == set(table["classes"])
    assert level_of(["read", "codemode"]) == "read"


def test_no_example_is_both_egress_and_send():
    table = yaml.safe_load((REPO / "homelabnext/agent/tool_classes.yml").read_text())

    def examples(cls):
        inside = table["classes"][cls].split("(", 1)[1].split(")", 1)[0]
        return {w.strip().removeprefix("a ").removeprefix("an ") for w in inside.split(",")}

    assert examples("egress") & examples("send") == set()


def test_cli_pack_with_profile_starts_a_session(profile, tmp_path, capsys):
    for name, doc in {"m.json": manifest(), "i.json": inputs(), "p.json": profile.data()}.items():
        (tmp_path / name).write_text(json.dumps(doc))
    policy, lock = write_policy_lock(tmp_path, profile)
    out = tmp_path / "pack.json"
    args = ["agent", "pack", str(tmp_path / "m.json"), "--inputs", str(tmp_path / "i.json")]
    reg = ["--registry", str(REPO / "examples" / "services.yml")]
    pl = ["--policy", str(policy), "--lock", str(lock)]
    prof = ["--profile", str(tmp_path / "p.json")]
    assert cli.main([*args, *prof, *pl, *reg, "--out", str(out)]) == 0
    pack = json.loads(out.read_text())["pack"]
    assert _section(pack, ACCESS_SECTION)["tier"] == "stable"
    assert cli.main([*args, *prof]) == 1
    assert "go together" in capsys.readouterr().err
    # a session starts only from a profile verified against the policy and the lock
    assert cli.main([*args, *prof, *reg]) == 1
    assert "--profile needs --policy and --lock" in capsys.readouterr().err
    edited = profile.data()
    edited["memory_scopes"] = ["analyst", "someone-else"]
    edited["digest"] = profile_digest(edited)
    (tmp_path / "p.json").write_text(json.dumps(edited))
    assert cli.main([*args, *prof, *pl, *reg, "--out", str(out)]) == 1
    assert "is not the reviewed" in capsys.readouterr().err
    assert cli.main([*args, *pl]) == 1
    assert "go with --profile" in capsys.readouterr().err


# ------------------------------------------------------------------ lint pairs manifests (G-03)


def _pair_case(case):
    """``(manifest, profile dict)`` for one mismatch ``start_session`` refuses."""
    m, p = manifest(), compile_profile(spec(), library())
    m["profiles"] = ["profile:reader"]
    if case == "actor-fed-raw-input":
        p = compile_profile({**spec(), "reads_untrusted": False}, library())
    elif case == "tools-beyond-grants":
        m["tools"] = ["lake", "records"]
    elif case == "memory-beyond-scopes":
        m["memory_scopes"] = ["analyst", "someone-else"]
    elif case == "persona":
        m["persona"] = "persona:someone-else"
    elif case == "not-named":
        m["profiles"] = ["profile:someone-else"]
    return m, p


PAIR_CASES = [
    "actor-fed-raw-input",
    "tools-beyond-grants",
    "memory-beyond-scopes",
    "persona",
    "not-named",
]


@pytest.mark.parametrize("case", PAIR_CASES)
def test_lint_finds_what_start_session_would_refuse(registry, tmp_path, case):
    """Parity: every problem the lint reports for a manifest and a profile it names is one that
    start_session refuses the session on, and the lint finds one for every refused pair."""
    from homelabnext.agent.readers import SESSIONS, lint_paths

    m, p = _pair_case(case)
    (tmp_path / "manifest.json").write_text(json.dumps(m))
    (tmp_path / "profile.json").write_text(json.dumps(p))
    with pytest.raises(SpecError) as refused:
        start_session(m, inputs(), verified(p), registry)
    by_rule: dict = {}
    problems, counts = lint_paths(
        [tmp_path / "manifest.json", tmp_path / "profile.json"], rules=[SESSIONS], by_rule=by_rule
    )
    if case == "not-named":  # no linted profile has the id the manifest names
        assert len(problems) == 1 and "which no linted profile has" in problems[0][1]
        assert "names profiles ['profile:someone-else'], not profile:reader" in str(refused.value)
        return
    assert counts == {"profile": 1, "manifest": 1} and problems == by_rule[SESSIONS]
    assert problems, f"lint missed what start_session refused: {refused.value}"
    for _, prob in problems:
        assert prob.split("): ", 1)[1] in str(refused.value)


def test_a_manifest_that_names_its_profile_lints_clean_and_one_that_names_none_is_a_note(
    tmp_path,
):
    from homelabnext.agent.readers import SESSIONS, lint_paths

    m, p = _pair_case("ok")
    (tmp_path / "manifest.json").write_text(json.dumps(m))
    (tmp_path / "profile.json").write_text(json.dumps(p))
    notes: list = []
    assert lint_paths([tmp_path], notes=notes, rules=[SESSIONS])[0] == []
    assert notes == []
    del m["profiles"]
    (tmp_path / "manifest.json").write_text(json.dumps(m))
    assert lint_paths([tmp_path], notes=notes, rules=[SESSIONS])[0] == []
    assert any("names no profiles" in n for _, n in notes)


def test_the_example_manifests_name_their_profiles_and_fit_them():
    from homelabnext.agent.readers import SESSIONS, lint_paths

    notes: list = []
    problems, counts = lint_paths(
        [REPO / "schemas" / "agent" / "examples"], notes, rules=[SESSIONS]
    )
    assert problems == [] and counts["manifest"] >= 2
    assert not [n for _, n in notes if "names no profiles" in n]


def test_start_session_refuses_a_profile_the_manifest_does_not_name(profile, registry):
    m = manifest()
    m["profiles"] = ["profile:someone-else"]
    with pytest.raises(SpecError, match=r"names profiles \['profile:someone-else'\]"):
        start_session(m, inputs(), profile, registry)
    m["profiles"] = ["profile:reader"]
    assert start_session(m, inputs(), profile, registry)[0]["status"] == "ready"


def test_a_session_refuses_an_input_section_declared_stable(profile, registry):
    m = manifest()
    next(s for s in m["sections"] if s["name"] == "findings")["tier"] = "stable"
    assert any("'findings'" in p and "tier: stable" in p for p in session_problems(m, profile))
    with pytest.raises(SpecError, match="tier: stable"):
        start_session(m, inputs(), profile, registry)


def test_a_session_refuses_a_delimiter_that_cannot_fence_input(profile, registry):
    m = manifest()
    m["delimiter"] = "ab\ncd"
    assert any("line break" in p for p in session_problems(m, profile))
    with pytest.raises(SpecError, match="line break"):
        start_session(m, inputs(), profile, registry)


def test_start_session_ages_pre_gates_against_its_now(profile, registry):
    from datetime import datetime

    late = datetime.fromisoformat("2026-01-15T10:15:01+00:00")
    pack, _ = start_session(manifest(), inputs(), profile, registry, now=lambda: late)
    assert pack["status"] == "deferred"
    assert any("over max_age_s" in r for r in pack["deferred_reasons"])


def test_cli_pack_ages_pre_gates_at_now(tmp_path, capsys):
    for name, doc in {"m.json": manifest(), "i.json": inputs()}.items():
        (tmp_path / name).write_text(json.dumps(doc))
    args = ["agent", "pack", str(tmp_path / "m.json"), "--inputs", str(tmp_path / "i.json")]
    out = ["--out", str(tmp_path / "pack.json")]
    assert cli.main([*args, *out, "--now", "2026-01-15T10:15:00Z"]) == 0
    assert cli.main([*args, *out, "--now", "2026-01-15T10:15:01+00:00"]) == 3
    assert "over max_age_s=900" in capsys.readouterr().err
    for bad in ("2026-01-15T10:15:00", "tomorrow"):  # usage error: no offset, not a time
        assert cli.main([*args, *out, "--now", bad]) == 2
        assert "RFC 3339 time with an offset" in capsys.readouterr().err


def _hosts_only_registry(tmp_path, *, runners=1):
    """A registry no service row of which carries ``agent-runtime``, with ``runners`` hosts of
    role ``agent-runtime`` (the example's ``runtime-core`` and copies of it at free addresses)."""
    doc = yaml.safe_load((REPO / "examples" / "services.yml").read_text())
    doc["services"] = {
        k: v for k, v in doc["services"].items() if v.get("capability") != "agent-runtime"
    }
    base = doc["hosts"]["runtime-core"]
    used = {h["address"] for h in doc["hosts"].values()}
    addr = ipaddress.ip_address(base["address"])
    for n in range(2, runners + 1):
        while str(addr) in used:
            addr += 1
        used.add(str(addr))
        doc["hosts"][f"runtime-{n}"] = {**base, "address": str(addr)}
    path = tmp_path / "services.yml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    return load(path)


def test_the_runner_host_is_found_by_host_role_with_no_agent_runtime_row(profile, tmp_path):
    reg = _hosts_only_registry(tmp_path)
    assert reg.by_capability("agent-runtime") is None
    block = access_block(profile, reg)
    assert block["runs_on"] == {"host": "runtime-core", "zone": "compute"}


def test_two_hosts_with_the_runner_role_are_refused_not_guessed(profile, tmp_path):
    reg = _hosts_only_registry(tmp_path, runners=2)
    with pytest.raises(SpecError, match=r"several registry hosts have role agent-runtime"):
        access_block(profile, reg)
    assert access_block(profile, reg, runs_on="runtime-2")["runs_on"]["host"] == "runtime-2"


def test_no_host_with_the_runner_role_is_refused(profile, tmp_path):
    doc = yaml.safe_load((REPO / "examples" / "services.yml").read_text())
    doc["hosts"]["runtime-core"]["role"] = "compute"
    path = tmp_path / "services.yml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    with pytest.raises(SpecError, match=r"no registry host has role agent-runtime"):
        access_block(profile, load(path))


def test_cli_pack_finds_the_runner_by_role_and_refuses_an_ambiguous_one(profile, tmp_path, capsys):
    for name, doc in {"m.json": manifest(), "i.json": inputs(), "p.json": profile.data()}.items():
        (tmp_path / name).write_text(json.dumps(doc))
    policy, lock = write_policy_lock(tmp_path, profile)
    out = tmp_path / "pack.json"
    args = ["agent", "pack", str(tmp_path / "m.json"), "--inputs", str(tmp_path / "i.json")]
    pl = ["--policy", str(policy), "--lock", str(lock), "--profile", str(tmp_path / "p.json")]
    _hosts_only_registry(tmp_path)
    reg = ["--registry", str(tmp_path / "services.yml")]
    assert cli.main([*args, *pl, *reg, "--out", str(out)]) == 0
    _hosts_only_registry(tmp_path, runners=2)
    assert cli.main([*args, *pl, *reg, "--out", str(out)]) == 1
    assert "several registry hosts have role agent-runtime" in capsys.readouterr().err
    assert cli.main([*args, *pl, *reg, "--runs-on", "runtime-2", "--out", str(out)]) == 0
