# SPDX-License-Identifier: Apache-2.0
"""``hnx secrets plan|seed`` (homelabnext/secretseed): find the names, create the missing values in
OpenBao (a fake on loopback) and copy them into Vaultwarden (a stub ``bw``), never overwriting a
value, never making one up for a name no rule classifies, and never putting one on a command line
or in the output."""

from __future__ import annotations

import json
import os
import string
import sys
import textwrap
from pathlib import Path

import pytest

from homelabnext.secretseed import (
    PASSWORD_ALPHABET,
    OpenBaoKV,
    Rule,
    SeedError,
    Spec,
    Vaultwarden,
    load_spec,
    scan,
    seed,
)
from homelabnext.secretseed.cli import main

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "overlay"))
from fake_openbao import FakeOpenBao

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "examples" / "private-overlay" / "lab" / "secrets.yml"
TOKEN = "fake-operator-token"
OFF_LOOPBACK = "openbao.example.internal"


def lab(tmp_path: Path) -> Path:
    d = tmp_path / "lab"
    (d / "guests").mkdir(parents=True)
    (d / "services.yml").write_text(
        textwrap.dedent(
            """\
            services:
              siem: {auth: {secret: "secret:siem/enrollment-password"}}
              ui: {key: secret:open-webui/session-key}
              # an example in a comment: secret:not/used
              mail: {password: x-secret:not/this/either}
            tailnet: {key: "secret:tailscale/deploy-key"}
            """
        )
    )
    (d / "guests" / "a.yml").write_text("token: secret:llm-gateway/key-chat-ui\n")
    (d / "notes.md").write_text("secret:markdown/ignored")
    ref = "secret:mcp/ssh-key"
    (d / "prose.yml").write_text(f"note: the key is {ref}.\n")
    return d


NAMES = [
    "llm-gateway/key-chat-ui",
    "mcp/ssh-key",
    "open-webui/session-key",
    "siem/enrollment-password",
    "tailscale/deploy-key",
]


def test_scan_finds_every_name_once_with_where_and_skips_comments_and_punctuation(tmp_path):
    found = scan([lab(tmp_path)])
    assert list(found) == NAMES
    assert found["siem/enrollment-password"][0].endswith("services.yml:2")


def test_a_missing_path_is_an_error_not_an_empty_plan(tmp_path):
    with pytest.raises(SeedError, match="no such file"):
        scan([tmp_path / "nope"])


# -------------------------------------------------------------------------------- the spec
def test_the_template_classifies_the_repository_s_names():
    spec = load_spec(TEMPLATE)
    kinds = {
        "tailscale/deploy-key": "external",
        "llm-gateway/master-key": "token",
        "llm-gateway/key-chat-ui": "token",
        "llm-gateway/database-url": "external",
        "mcp/github-token": "external",
        "mcp/ssh-key": "external",
        "mcp/kubeconfig": "external",
        "publishing/deny-list": "external",
        "open-webui/session-key": "token",
        "siem/enrollment-password": "password",
        "ansible/vault-password": "password",
        "anything/else": "unclassified",
    }
    assert {n: spec.rule(n).kind for n in kinds} == kinds
    assert spec.rule("llm-gateway/master-key").prefix == "sk-"
    assert "ansible/vault-password" in spec.also
    assert not spec.to_vaultwarden("status/ingest/agent-fleet-token")


def test_every_name_the_roles_use_is_classified():
    """A role's default secret name gets a deliberate rule: the template covers them all."""
    spec = load_spec(TEMPLATE)
    found = scan([ROOT / "ansible" / "roles"])
    assert found and [n for n in found if spec.rule(n).kind == "unclassified"] == []


@pytest.mark.parametrize(
    ("body", "needle"),
    [
        (("secrets_version: 2",), "secrets_version: 1"),
        (("secrets_version: 1", "extra: 1"), "unknown key"),
        (("secrets_version: 1", "default: {kind: external, how: x}"), "cannot be external"),
        (("secrets_version: 1", "rules: [{match: 'a/*', kind: external}]"), "how to get it"),
        (("secrets_version: 1", "rules: [{match: 'a/*', length: 8}]"), "20 to 128"),
        (("secrets_version: 1", "rules: [{match: 'a/*', kind: hex, bytes: 4}]"), "16 to 128"),
        (("secrets_version: 1", "rules: [{match: 'a/*', prefix: 'sk-'}]"), "on a token only"),
        (("secrets_version: 1", "rules: [{kind: token}]"), "match is a glob"),
        (("secrets_version: 1", "rules: [{match: 'a/*', kind: pin}]"), "kind is one of"),
        (("secrets_version: 1", "also: ['Not A Name']"), "also is a list"),
        (("secrets_version: 1", "vaultwarden: {folder: ''}"), "folder name"),
        (("secrets_version: 1", "secrets_version: 1"), "cannot read"),
    ],
)
def test_a_bad_spec_is_refused(tmp_path, body, needle):
    p = tmp_path / "secrets.yml"
    p.write_text("\n".join(body) + "\n")
    with pytest.raises(SeedError, match=needle):
        load_spec(p)


def test_generated_values_have_their_shape_and_differ():
    pw = Rule("*", "password", length=40)
    a, b = pw.generate(), pw.generate()
    assert len(a) == 40 and set(a) <= set(PASSWORD_ALPHABET) and a != b
    tok = Rule("*", "token", nbytes=32, prefix="sk-").generate()
    assert tok.startswith("sk-") and len(tok) == 3 + 43
    hx = Rule("*", "hex", nbytes=20).generate()
    assert len(hx) == 40 and set(hx) <= set(string.hexdigits.lower())
    for kind in ("external", "unclassified"):
        with pytest.raises(SeedError):
            Rule("*", kind, how="x").generate()


# ------------------------------------------------------------------------------- OpenBao
def test_the_client_refuses_plain_http_off_loopback_and_no_token():
    with pytest.raises(SeedError, match="https"):
        OpenBaoKV(f"http://{OFF_LOOPBACK}", TOKEN)
    with pytest.raises(SeedError, match="BAO_TOKEN"):
        OpenBaoKV(f"https://{OFF_LOOPBACK}", "")
    with pytest.raises(SeedError, match="BAO_ADDR"):
        OpenBaoKV.from_env({})


def test_a_redirect_is_refused():
    with (
        FakeOpenBao(redirect_to="http://localhost", tokens=(TOKEN,)) as bao,
        pytest.raises(SeedError, match="307"),
    ):
        OpenBaoKV(bao.url, TOKEN).exists("siem/enrollment-password")


def test_a_kv_version_1_mount_is_refused_before_any_write():
    """Version 1 ignores check-and-set: a write there would overwrite. Nothing is written."""
    with FakeOpenBao(tokens=(TOKEN,), kv_version="1") as bao:
        out = seed(["a/b"], load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), given={"a/b": "v"})
        assert out[0].openbao == "error" and "not a KV version 2" in out[0].detail
        assert bao.values == {} and not [c for c in bao.calls if c[0] == "POST"]


def test_seed_creates_the_missing_keeps_the_present_and_lists_the_external(tmp_path):
    names = scan([lab(tmp_path)])
    keep = {"value": "an-existing-value-nobody-may-overwrite"}
    with FakeOpenBao({"secret/siem/enrollment-password": dict(keep)}, tokens=(TOKEN,)) as bao:
        kv = OpenBaoKV(bao.url, TOKEN)
        out = seed(names, load_spec(TEMPLATE), kv)
        assert {o.name: o.openbao for o in out} == {
            "llm-gateway/key-chat-ui": "created",
            "mcp/ssh-key": "needs-value",
            "open-webui/session-key": "created",
            "siem/enrollment-password": "exists",
            "tailscale/deploy-key": "needs-value",
        }
        assert bao.values["secret/siem/enrollment-password"] == keep
        assert bao.values["secret/llm-gateway/key-chat-ui"]["value"].startswith("sk-")
        assert "Tailscale admin console" in next(o for o in out if o.name.startswith("tail")).detail
        again = {o.name: o.openbao for o in seed(names, load_spec(TEMPLATE), kv)}
        assert again["open-webui/session-key"] == "exists"


def test_a_name_no_rule_classifies_is_never_made_up():
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(["vendor/api-key"], Spec(), OpenBaoKV(bao.url, TOKEN))
        assert out[0].openbao == "unclassified" and bao.values == {}


def test_a_soft_deleted_secret_is_reported_not_overwritten():
    with FakeOpenBao(tokens=(TOKEN,), deleted=("secret/a/b",)) as bao:
        out = seed(["a/b"], load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), given={"a/b": "v"})
        assert out[0].openbao == "error" and "deleted" in out[0].detail
        assert not [c for c in bao.calls if c[0] == "POST"]


def test_external_values_are_asked_for_or_read_from_files(tmp_path):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(
            ["tailscale/deploy-key", "mcp/ssh-key"],
            load_spec(TEMPLATE),
            OpenBaoKV(bao.url, TOKEN),
            ask=lambda name, rule: "tskey-auth-fake" if name.startswith("tail") else "",
            given={"mcp/ssh-key": "-----BEGIN FAKE KEY-----\nAAAA\n-----END FAKE KEY-----\n"},
        )
        assert [o.openbao for o in out] == ["created", "created"]
        assert bao.values["secret/tailscale/deploy-key"] == {"value": "tskey-auth-fake"}
        assert bao.values["secret/mcp/ssh-key"]["value"].count("\n") == 3


def test_a_dry_run_writes_nothing():
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(
            ["siem/x-password"], load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), dry_run=True
        )
        assert bao.values == {} and all(method == "GET" for method, _, _ in bao.calls)
        assert out[0].openbao == "unclassified"
        out = seed(["idp/admin"], load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), dry_run=True)
        assert out[0].openbao == "would-create" and bao.values == {}


def test_a_race_lost_on_check_and_set_keeps_the_winner():
    class Late(OpenBaoKV):
        def state(self, name):  # another run writes between our check and our write
            self.check_mount()
            return "missing"

    with FakeOpenBao({"secret/idp/a": {"value": "the-winner"}}, tokens=(TOKEN,)) as bao:
        out = seed(["idp/a"], load_spec(TEMPLATE), Late(bao.url, TOKEN))
        assert out[0].openbao == "exists" and bao.values["secret/idp/a"] == {"value": "the-winner"}


def test_a_refused_call_is_an_error_naming_no_value():
    with FakeOpenBao() as bao:  # the token is not live: 403
        out = seed(["idp/a"], load_spec(TEMPLATE), OpenBaoKV(bao.url, "not-a-live-token"))
        assert out[0].openbao == "error" and "403" in out[0].detail


# ---------------------------------------------------------------------------- Vaultwarden
BW_STUB = r"""#!/usr/bin/env python3
import base64, json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
state_path, log = os.path.join(here, "bw-state.json"), os.path.join(here, "bw-log.jsonl")
args = [a for a in sys.argv[1:] if a != "--nointeraction"]
with open(log, "a") as f:
    f.write(json.dumps({"argv": args, "env": sorted(os.environ)}) + "\n")
state = json.load(open(state_path)) if os.path.exists(state_path) else {"folders": [], "items": []}
def save():
    json.dump(state, open(state_path, "w"))
if args[0] == "sync":
    print("Syncing complete.")
elif args[:2] == ["list", "folders"]:
    print(json.dumps([f for f in state["folders"] if args[3] in f["name"]]))
elif args[:2] == ["list", "items"]:
    print(json.dumps([i for i in state["items"] if i["folderId"] == args[3]]))
elif args[0] == "encode":
    print(base64.b64encode(sys.stdin.read().encode()).decode())
elif args[:2] == ["create", "folder"]:
    doc = json.loads(base64.b64decode(sys.stdin.read()))
    doc["id"] = f"folder-{len(state['folders'])}"
    state["folders"].append(doc); save(); print(json.dumps(doc))
elif args[:2] == ["create", "item"]:
    data = sys.stdin.read()
    if os.path.exists(os.path.join(here, "bw-fail")):
        sys.exit("refused: " + data)  # a bw that echoes its input on error
    doc = json.loads(base64.b64decode(data))
    state["items"].append(doc); save(); print(json.dumps(doc))
else:
    sys.exit(f"unexpected {args}")
"""


@pytest.fixture
def bw(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "bw").write_text(BW_STUB)
    (bindir / "bw").chmod(0o755)
    monkeypatch.setenv("BW_SESSION", "fake-session")
    monkeypatch.setenv("BAO_TOKEN", TOKEN)
    monkeypatch.setenv("PATH", f"{bindir}:" + os.environ["PATH"])
    return bindir / "bw-state.json", bindir / "bw-log.jsonl", bindir


def test_vaultwarden_gets_a_copy_of_every_value_and_no_value_or_token_reaches_bw_otherwise(
    tmp_path, bw
):
    state, log, _ = bw
    names = scan([lab(tmp_path)])
    with FakeOpenBao(
        {"secret/siem/enrollment-password": {"value": "pre-existing"}}, tokens=(TOKEN,)
    ) as bao:
        out = seed(names, load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), Vaultwarden("homelab"))
        values = {k.removeprefix("secret/"): v["value"] for k, v in bao.values.items()}
    assert {o.name: o.vaultwarden for o in out} == {
        "llm-gateway/key-chat-ui": "created",
        "mcp/ssh-key": "-",  # no value yet
        "open-webui/session-key": "created",
        "siem/enrollment-password": "created",  # existing in OpenBao: read and copied
        "tailscale/deploy-key": "-",
    }
    doc = json.loads(state.read_text())
    assert [f["name"] for f in doc["folders"]] == ["homelab"]
    items = {i["name"]: i for i in doc["items"]}
    for name, value in values.items():
        assert items[f"secret:{name}"]["login"]["password"] == value
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert not any(v in json.dumps(c["argv"]) for c in calls for v in values.values())
    assert all("BAO_TOKEN" not in c["env"] for c in calls)


def test_vaultwarden_keeps_what_it_has_and_honours_the_exclusions(bw):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        kv = OpenBaoKV(bao.url, TOKEN)
        seed(["idp/a"], load_spec(TEMPLATE), kv, Vaultwarden("homelab"))
        out = seed(
            ["idp/a", "status/ingest/x-token"], load_spec(TEMPLATE), kv, Vaultwarden("homelab")
        )
    assert {o.name: o.vaultwarden for o in out} == {
        "idp/a": "exists",
        "status/ingest/x-token": "skipped",
    }


def test_a_dry_run_creates_nothing_in_vaultwarden(bw):
    state, log, _ = bw
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(
            ["idp/a"], load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN),
            Vaultwarden("homelab", dry_run=True), dry_run=True,
        )  # fmt: skip
    assert out[0].vaultwarden == "would-create" and not state.exists()
    assert not any(json.loads(c)["argv"][0] == "create" for c in log.read_text().splitlines())


def test_a_bw_failure_never_echoes_what_it_was_given(bw):
    _, _, bindir = bw
    (bindir / "bw-fail").touch()
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(
            ["idp/a"], load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), Vaultwarden("homelab")
        )
        value = bao.values["secret/idp/a"]["value"]
    assert out[0].vaultwarden == "error" and "exit 1" in out[0].detail
    assert value not in out[0].detail and "refused" not in out[0].detail


def test_vaultwarden_needs_an_unlocked_session(monkeypatch):
    monkeypatch.delenv("BW_SESSION", raising=False)
    with pytest.raises(SeedError, match="bw unlock"):
        Vaultwarden("homelab")


# ------------------------------------------------------------------------------------- CLI
def test_plan_lists_names_kinds_and_the_unclassified(tmp_path, capsys):
    ref = "secret:vendor/api-key"
    (lab(tmp_path) / "x.yml").write_text(f"k: {ref}\n")
    assert main(["plan", str(tmp_path / "lab"), "--spec", str(TEMPLATE)]) == 0
    out = capsys.readouterr().out
    assert "external     secret:tailscale/deploy-key" in out
    assert "unclassified secret:vendor/api-key" in out
    assert "secret:ansible/vault-password" in out  # the spec's also
    assert "7 secret(s); 1 unclassified" in out


@pytest.fixture
def bao_env(monkeypatch):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        monkeypatch.setenv("BAO_ADDR", bao.url)
        monkeypatch.setenv("BAO_TOKEN", TOKEN)
        yield bao


def test_seed_needs_a_yes_off_a_terminal_and_writes_nothing_without_it(tmp_path, bao_env, capsys):
    assert main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE)]) == 1
    assert bao_env.values == {} and "pass --yes" in capsys.readouterr().err


def test_seed_prints_names_never_values_and_exits_3_while_values_are_owed(
    tmp_path, bao_env, capsys
):
    rc = main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE), "--yes"])
    values = [v["value"] for v in bao_env.values.values()]
    out = capsys.readouterr().out
    assert rc == 3 and "6 secret(s); 0 error(s); 2 still need a value or a rule" in out
    assert values and not any(v in out for v in values)


def test_seed_with_every_external_given_exits_0(tmp_path, bao_env, capsys):
    key, tsk = tmp_path / "key", tmp_path / "ts"
    key.write_text("fake-key-material\n")
    tsk.write_text("tskey-auth-fake")
    args = ["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE), "--yes"]
    args += [
        "--from-file",
        f"mcp/ssh-key={key}",
        "--from-file",
        "secret:" + f"tailscale/deploy-key={tsk}",
    ]
    assert main(args) == 0
    assert bao_env.values["secret/mcp/ssh-key"] == {"value": "fake-key-material\n"}


def test_ask_off_a_terminal_says_so(tmp_path, bao_env, capsys):
    rc = main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE), "--yes", "--ask"])
    assert rc == 3 and "--ask needs a terminal" in capsys.readouterr().err


@pytest.mark.parametrize("pair", ["no-equals", "BAD NAME=x", "a/b="])
def test_a_bad_from_file_is_a_usage_error(tmp_path, bao_env, pair, capsys):
    assert main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE), "--from-file", pair]) == 2


def test_seed_without_openbao_settings_is_a_usage_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BAO_ADDR", raising=False)
    assert main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE)]) == 2
    assert "BAO_ADDR is not set" in capsys.readouterr().err
