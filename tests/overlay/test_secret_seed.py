# SPDX-License-Identifier: Apache-2.0
"""``hnx secrets plan|seed`` (homelabnext/secretseed): find the names, create the missing values in
OpenBao (a fake on loopback) and copy them into Vaultwarden (a stub ``bw``), never overwriting a
value and never putting one on a command line or in the output."""

from __future__ import annotations

import json
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_openbao import FakeOpenBao

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "examples" / "private-overlay" / "lab" / "secrets.yml"
TOKEN = "fake-operator-token"


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
            tailnet: {key: "secret:tailscale/deploy-key"}
            """
        )
    )
    (d / "guests" / "a.yml").write_text("token: secret:llm-gateway/key-chat-ui\n")
    (d / "notes.md").write_text("secret:markdown/ignored")
    return d


def test_scan_finds_every_name_once_with_where_and_skips_comments(tmp_path):
    found = scan([lab(tmp_path)])
    assert list(found) == [
        "llm-gateway/key-chat-ui",
        "open-webui/session-key",
        "siem/enrollment-password",
        "tailscale/deploy-key",
    ]
    assert found["siem/enrollment-password"][0].endswith("services.yml:2")


def test_a_missing_path_is_an_error_not_an_empty_plan(tmp_path):
    with pytest.raises(SeedError, match="no such file"):
        scan([tmp_path / "nope"])


# -------------------------------------------------------------------------------- the spec
def test_the_template_loads_and_classifies_the_repository_s_names():
    spec = load_spec(TEMPLATE)
    assert spec.rule("tailscale/deploy-key").kind == "external"
    assert spec.rule("llm-gateway/key-chat-ui").prefix == "sk-"
    assert spec.rule("open-webui/session-key").kind == "token"
    assert spec.rule("siem/enrollment-password").kind == "password"
    assert spec.rule("anything/else").kind == "password"
    assert not spec.to_vaultwarden("status/ingest/agent-fleet-token")


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
    with pytest.raises(SeedError):
        Rule("*", "external", how="x").generate()


# ------------------------------------------------------------------------------- OpenBao
def test_the_client_refuses_plain_http_off_loopback_and_no_token():
    with pytest.raises(SeedError, match="https"):
        OpenBaoKV("http://bao.example.internal:8200", TOKEN)
    with pytest.raises(SeedError, match="BAO_TOKEN"):
        OpenBaoKV("https://bao.example.internal:8200", "")
    with pytest.raises(SeedError, match="BAO_ADDR"):
        OpenBaoKV.from_env({})


def test_a_redirect_is_refused():
    with FakeOpenBao(redirect_to="http://127.0.0.1:9", tokens=(TOKEN,)) as bao:
        kv = OpenBaoKV(bao.url, TOKEN)
        with pytest.raises(SeedError, match="307"):
            kv.exists("siem/enrollment-password")


def test_seed_creates_the_missing_keeps_the_present_and_lists_the_external(tmp_path):
    names = scan([lab(tmp_path)])
    keep = {"value": "an-existing-value-nobody-may-overwrite"}
    with FakeOpenBao({"secret/siem/enrollment-password": dict(keep)}, tokens=(TOKEN,)) as bao:
        out = seed(names, load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN))
        got = {o.name: o.openbao for o in out}
        assert got == {
            "llm-gateway/key-chat-ui": "created",
            "open-webui/session-key": "created",
            "siem/enrollment-password": "exists",
            "tailscale/deploy-key": "needs-value",
        }
        assert bao.values["secret/siem/enrollment-password"] == keep
        assert bao.values["secret/llm-gateway/key-chat-ui"]["value"].startswith("sk-")
        assert "Tailscale admin console" in next(o for o in out if o.kind == "external").detail
        # a second run changes nothing
        again = {
            o.name: o.openbao for o in seed(names, load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN))
        }
        assert again["open-webui/session-key"] == "exists"


def test_an_external_value_is_asked_for(tmp_path):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(
            ["tailscale/deploy-key"],
            load_spec(TEMPLATE),
            OpenBaoKV(bao.url, TOKEN),
            ask=lambda name, rule: "tskey-auth-fake",
        )
        assert out[0].openbao == "created"
        assert bao.values["secret/tailscale/deploy-key"] == {"value": "tskey-auth-fake"}


def test_a_dry_run_writes_nothing(tmp_path):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        out = seed(["a/b"], Spec(), OpenBaoKV(bao.url, TOKEN), dry_run=True)
        assert out[0].openbao == "would-create" and bao.values == {}
        assert all(method == "GET" for method, _, _ in bao.calls)


def test_a_race_lost_on_check_and_set_keeps_the_winner(tmp_path):
    class Late(OpenBaoKV):
        def exists(self, name):  # another run writes between our check and our write
            return False

    with FakeOpenBao({"secret/a/b": {"value": "the-winner"}}, tokens=(TOKEN,)) as bao:
        out = seed(["a/b"], Spec(), Late(bao.url, TOKEN))
        assert out[0].openbao == "exists" and bao.values["secret/a/b"] == {"value": "the-winner"}


def test_a_refused_write_is_an_error_naming_no_value(tmp_path):
    with FakeOpenBao() as bao:  # the token is not live: 403
        out = seed(["a/b"], Spec(), OpenBaoKV(bao.url, "not-a-live-token"))
        assert out[0].openbao == "error" and "403" in out[0].detail


# ---------------------------------------------------------------------------- Vaultwarden
BW_STUB = r"""#!/usr/bin/env python3
import base64, json, os, sys
state_path, log = os.environ["BW_STATE"], os.environ["BW_LOG"]
args = [a for a in sys.argv[1:] if a != "--nointeraction"]
with open(log, "a") as f:
    f.write(json.dumps(args) + "\n")
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
    doc = json.loads(base64.b64decode(sys.stdin.read()))
    state["items"].append(doc); save(); print(json.dumps(doc))
else:
    sys.exit(f"unexpected {args}")
"""


@pytest.fixture
def bw(tmp_path, monkeypatch):
    stub = tmp_path / "bw"
    stub.write_text(BW_STUB)
    stub.chmod(0o755)
    state, log = tmp_path / "bw-state.json", tmp_path / "bw-log.jsonl"
    env = {"BW_SESSION": "fake-session", "BW_STATE": str(state), "BW_LOG": str(log)}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PATH", f"{tmp_path}:" + __import__("os").environ["PATH"])
    return state, log


def test_vaultwarden_gets_a_copy_of_every_value_and_no_value_is_ever_an_argument(tmp_path, bw):
    state, log = bw
    names = scan([lab(tmp_path)])
    with FakeOpenBao(
        {"secret/siem/enrollment-password": {"value": "pre-existing"}}, tokens=(TOKEN,)
    ) as bao:
        vault = Vaultwarden("homelab")
        out = seed(names, load_spec(TEMPLATE), OpenBaoKV(bao.url, TOKEN), vault)
        values = {k.removeprefix("secret/"): v["value"] for k, v in bao.values.items()}
    assert {o.name: o.vaultwarden for o in out} == {
        "llm-gateway/key-chat-ui": "created",
        "open-webui/session-key": "created",
        "siem/enrollment-password": "created",  # existing in OpenBao: read and copied
        "tailscale/deploy-key": "-",  # no value yet
    }
    doc = json.loads(state.read_text())
    assert [f["name"] for f in doc["folders"]] == ["homelab"]
    items = {i["name"]: i for i in doc["items"]}
    for name, value in values.items():
        assert items[f"secret:{name}"]["login"]["password"] == value
        assert items[f"secret:{name}"]["folderId"] == "folder-0"
    argv = log.read_text()
    assert not any(v in argv for v in values.values())


def test_vaultwarden_keeps_what_it_has_and_honours_the_exclusions(tmp_path, bw):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        kv = OpenBaoKV(bao.url, TOKEN)
        seed(["a/b"], Spec(), kv, Vaultwarden("homelab"))
        out = seed(
            ["a/b", "status/ingest/x-token"], load_spec(TEMPLATE), kv, Vaultwarden("homelab")
        )
    assert {o.name: o.vaultwarden for o in out} == {
        "a/b": "exists",
        "status/ingest/x-token": "skipped",
    }


def test_vaultwarden_needs_an_unlocked_session(monkeypatch):
    monkeypatch.delenv("BW_SESSION", raising=False)
    with pytest.raises(SeedError, match="bw unlock"):
        Vaultwarden("homelab")


# ------------------------------------------------------------------------------------- CLI
def test_plan_lists_names_and_kinds(tmp_path, capsys):
    assert main(["plan", str(lab(tmp_path)), "--spec", str(TEMPLATE)]) == 0
    out = capsys.readouterr().out
    assert "external  secret:tailscale/deploy-key" in out and "4 secret(s)" in out


def test_seed_from_the_command_line_prints_names_never_values(tmp_path, capsys, monkeypatch):
    with FakeOpenBao(tokens=(TOKEN,)) as bao:
        monkeypatch.setenv("BAO_ADDR", bao.url)
        monkeypatch.setenv("BAO_TOKEN", TOKEN)
        rc = main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE)])
        values = [v["value"] for v in bao.values.values()]
    out = capsys.readouterr().out
    assert rc == 0 and "4 secret(s); 0 error(s); 1 external still need a value" in out
    assert values and not any(v in out for v in values)


def test_seed_without_openbao_settings_is_a_usage_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BAO_ADDR", raising=False)
    assert main(["seed", str(lab(tmp_path)), "--spec", str(TEMPLATE)]) == 2
    assert "BAO_ADDR is not set" in capsys.readouterr().err
