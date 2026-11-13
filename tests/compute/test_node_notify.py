# SPDX-License-Identifier: Apache-2.0
"""Hypervisor notifications to ntfy (``_nodes.yml`` ``notify``, target ``node-notify``): loading,
rendering, and the generated script run against a ``pvesh`` stub that keeps the notification
config the way Proxmox does (one entry per path; create refuses an existing name)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.compute import ComputeError, load_fleet, load_nodes, render
from homelabnext.compute.gen import node_notify
from homelabnext.compute.zones import MappingZones, ZoneInfo

FLEET = Path(__file__).resolve().parent / "fleet"
STUB = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)

NOTIFY = {"url": "https://notify.example.org", "topic": "node-alerts"}


def nodes_file(tmp_path: Path, nodes: dict) -> Path:
    p = tmp_path / "_nodes.yml"
    p.write_text(yaml.safe_dump({"nodes": nodes}), encoding="utf-8")
    return p


def fleet_with(tmp_path: Path, nodes: dict):
    return load_fleet(FLEET, STUB, nodes_path=nodes_file(tmp_path, nodes))


def test_defaults_fill_in(tmp_path):
    got = load_nodes(nodes_file(tmp_path, {"hv-a": {"notify": NOTIFY}}))["hv-a"]["notify"]
    assert got == {
        "url": "https://notify.example.org/",
        "topic": "node-alerts",
        "severities": ["warning", "error", "unknown"],
        "priority": 4,
        "default_mail": False,
    }


@pytest.mark.parametrize(
    ("notify", "needle"),
    [
        ({"url": "https://notify.example.org"}, "url and topic"),
        ({**NOTIFY, "token": "x"}, "url and topic"),
        ({**NOTIFY, "url": "ftp://notify.example.org"}, "not an http"),
        ({**NOTIFY, "url": "https://user:pw@notify.example.org"}, "not an http"),
        ({**NOTIFY, "url": "https://notify.example.org/?a=1"}, "not an http"),
        ({**NOTIFY, "url": 'https://x"$(id)'}, "not an http"),
        ({**NOTIFY, "url": "https://notify.example.org\n"}, "not an http"),
        ({**NOTIFY, "url": "https://a..b/"}, "not an http"),
        ({**NOTIFY, "url": "https://notify.example.org/../x"}, "not an http"),
        ({**NOTIFY, "url": "https://notify.example.org:0/"}, "not an http"),
        ({**NOTIFY, "url": "https://notify.example.org:65536/"}, "not an http"),
        ({**NOTIFY, "url": "https://notify.example.org/#x"}, "not an http"),
        ({**NOTIFY, "url": 443}, "not an http"),
        ({**NOTIFY, "topic": "alerts\n"}, "not a topic"),
        ({**NOTIFY, "topic": 7}, "not a topic"),
        ({**NOTIFY, "topic": "a/b"}, "not a topic"),
        ({**NOTIFY, "topic": "a" * 65}, "not a topic"),
        ({**NOTIFY, "severities": []}, "non-empty list"),
        ({**NOTIFY, "severities": ["critical"]}, "non-empty list"),
        ({**NOTIFY, "severities": ["error", "error"]}, "listed twice"),
        ({**NOTIFY, "priority": 6}, "1 to 5"),
        ({**NOTIFY, "priority": True}, "1 to 5"),
        ({**NOTIFY, "default_mail": "no"}, "true or false"),
        ({**NOTIFY, "credential": "token"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:Token"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:a-b"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:a.b"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:a b"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:a\n"}, "secret reference"),
        ({**NOTIFY, "credential": "secret:" + "a" * 33}, "secret reference"),
        ({**NOTIFY, "credential": 7}, "secret reference"),
    ],
)
def test_a_bad_notify_is_refused(tmp_path, notify, needle):
    with pytest.raises(ComputeError, match=needle):
        load_nodes(nodes_file(tmp_path, {"hv-a": {"notify": notify}}))


def test_no_notify_renders_only_a_readme(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {}}), "node-notify")
    assert list(out) == ["notify/README.md"]
    assert "No node declares `notify`" in out["notify/README.md"]


def test_a_notifying_node_gets_a_script(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}, "hv-b": {}}), "node-notify")
    assert sorted(out) == ["notify/README.md", "notify/hv-a/hnx-notify.sh"]
    sh = out["notify/hv-a/hnx-notify.sh"]
    assert 'URL="https://notify.example.org/"' in sh
    assert 'SEVERITIES="warning,error,unknown"' in sh
    assert (
        "| `hv-a` | `https://notify.example.org/` | `node-alerts` "
        "| `warning`, `error`, `unknown` | turned off | none |" in out["notify/README.md"]
    )


def test_the_body_is_json_once_the_hypervisor_fills_it(tmp_path):
    sh = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}}), "node-notify")[
        "notify/hv-a/hnx-notify.sh"
    ]
    line = next(x for x in sh.splitlines() if x.startswith('BODY="'))
    template = base64.b64decode(line[len('BODY="') : -1]).decode()
    # what Proxmox's escape helper produces: JSON string content
    filled = (
        template.replace("{{ escape title }}", json.dumps('backup "failed"')[1:-1])
        .replace("{{ escape message }}", json.dumps("line 1\nline 2")[1:-1])
        .replace("{{ severity }}", "error")
    )
    doc = json.loads(filled)
    assert doc == {
        "topic": "node-alerts",
        "title": '[hv-a] backup "failed"',
        "message": "line 1\nline 2",
        "priority": 4,
        "tags": ["hypervisor", "error"],
    }


def test_a_notifying_node_name_must_be_a_path_safe_node_name(tmp_path):
    with pytest.raises(ComputeError, match="must be one a guest can name"):
        render(fleet_with(tmp_path, {"../etc": {"notify": NOTIFY}}), "node-notify")


def test_the_target_is_per_node_and_not_made_of_guests():
    assert node_notify.PER_NODE is True and node_notify.RENDERS_GUESTS is False


def test_the_names_carry_the_node_and_differ():
    # one namespace for both in notifications.cfg, and one file for every node of a cluster
    target, matcher = node_notify.names("hv-a")
    assert target != matcher
    assert set(node_notify.names("hv-a")).isdisjoint(node_notify.names("hv-b"))


def test_the_matcher_answers_only_for_its_node(tmp_path):
    sh = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}}), "node-notify")[
        "notify/hv-a/hnx-notify.sh"
    ]
    assert 'NODE="hv-a"' in sh and '--match-field "exact:hostname=$NODE"' in sh


def test_a_good_url_with_port_and_path_loads(tmp_path):
    url = "http://192.0.2.10:8080/notify"
    got = load_nodes(nodes_file(tmp_path, {"hv-a": {"notify": {**NOTIFY, "url": url}}}))
    assert got["hv-a"]["notify"]["url"] == url + "/"


def test_the_target_is_a_per_node_target_not_made_of_guests():
    from homelabnext.compute.cli import GUEST_TARGETS, PER_NODE_TARGETS

    assert "node-notify" in PER_NODE_TARGETS and "node-notify" not in GUEST_TARGETS


@pytest.mark.requires_tool("shellcheck")
def test_the_script_passes_shellcheck(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}}), "node-notify")
    script = tmp_path / "hnx-notify.sh"
    script.write_text(out["notify/hv-a/hnx-notify.sh"], encoding="utf-8")
    subprocess.run(["shellcheck", "-s", "sh", str(script)], check=True)


# ------------------------------------------------------- the script against a fake pvesh
# Each config entry is a file named after its API path; ``create`` refuses a name any target or
# matcher already has (they share one namespace in notifications.cfg), ``set`` and ``delete`` need
# the entry to exist (the built-in default-matcher is seeded), ``--delete`` takes one key per
# flag and may repeat (pvesh 9 refuses ``--delete a,b``: "invalid configuration ID 'a,b'"), each
# key one the entry has, and ``--match-severity`` is one comma-joined list of Proxmox severities
# (the form the live node took).  ``--header`` and ``--secret`` are ``name=...,value=...`` property
# strings, a secret's value base64.  Each entry keeps the arguments of its last create or set.
# ``$STATE.testfail`` fails the test, ``$STATE.deletefail`` every delete.
PVESH_STUB = r"""#!/bin/sh
echo "pvesh $*" >> "$LOG"
verb="$1" path="$2"; shift 2
f="$STATE$(printf '%s' "$path" | tr / _)"
check_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --delete)
        case "$2" in
          disable|secret|header|comment|invert-match|match-calendar|match-field|match-severity) ;;
          *) echo "invalid configuration ID '$2'" >&2; exit 255 ;;
        esac ;;
      --header)
        case "$2" in name=?*,value=?*) ;; *) echo "header: bad property string" >&2; exit 255 ;; esac ;;
      --secret)
        case "$2" in
          name=?*,value=?*) v="${2#*,value=}"
            printf '%s' "$v" | base64 -d >/dev/null 2>&1 || { echo "secret: not base64" >&2; exit 255; } ;;
          *) echo "secret: bad property string" >&2; exit 255 ;;
        esac ;;
      --match-severity)
        [ -n "$2" ] || { echo "match-severity: empty" >&2; exit 255; }
        for s in $(printf '%s' "$2" | tr , ' '); do
          case "$s" in info|notice|warning|error|unknown) ;;
            *) echo "match-severity: value '$s' does not match the regex" >&2; exit 255 ;;
          esac
        done
        case "$2" in ,*|*,|*,,*) echo "match-severity: empty item" >&2; exit 255 ;; esac ;;
    esac
    shift
  done
}
case "$verb" in
  get) [ -e "$f" ] ;;
  create)
    case "$path" in */test) [ -e "$STATE.testfail" ] && { echo "500 Could not test target" >&2; exit 115; }; exit 0 ;; esac
    check_args "$@"
    name=""
    while [ "$#" -gt 0 ]; do [ "$1" = --name ] && name="$2"; shift; done
    for e in "$STATE"*_"$name"; do
      [ -e "$e" ] && { echo "an entity with the same name already exists" >&2; exit 255; }
    done
    printf '%s\n' "$*" > "$f"_"$name" ;;
  set)
    [ -e "$f" ] || { echo "not found" >&2; exit 255; }
    check_args "$@"
    printf '%s\n' "$*" > "$f" ;;
  delete)
    [ -e "$STATE.deletefail" ] && { echo "500 could not delete" >&2; exit 255; }
    rm "$f" ;;
esac
"""


@pytest.fixture
def node(tmp_path):
    """The rendered script, a ``pvesh`` stub on PATH and a runner returning (result, calls)."""
    state = tmp_path / "state"
    state.mkdir()
    (Path(f"{state}_cluster_notifications_matchers_default-matcher")).touch()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "pvesh").write_text(PVESH_STUB, encoding="utf-8")
    (bin_ / "pvesh").chmod(0o755)
    log = tmp_path / "calls.log"

    def setup(spec: dict):
        out = render(fleet_with(tmp_path, {"hv-a": {"notify": spec}}), "node-notify")
        script = tmp_path / "hnx-notify.sh"
        script.write_text(out["notify/hv-a/hnx-notify.sh"], encoding="utf-8")
        env = {
            **os.environ,
            "PATH": f"{bin_}:{os.environ['PATH']}",
            "LOG": str(log),
            "STATE": str(state),
        }

        def run(*args: str, extra_env: dict | None = None, stdin: str | None = None):
            log.write_text("")
            r = subprocess.run(
                ["sh", str(script), *args],
                env={**env, **(extra_env or {})},
                capture_output=True,
                text=True,
                # never the test runner's own stdin: the script reads a credential from a pipe
                **({"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}),
            )
            return r, log.read_text().splitlines()

        run.script = script
        return run

    setup.bin = str(bin_)
    setup.state = str(state)
    return setup


def _verbs(calls: list[str]) -> list[str]:
    return [" ".join(c.split()[:3]) for c in calls if not c.startswith("pvesh get")]


def test_the_first_run_creates_and_turns_off_the_mail_matcher(node):
    run = node(NOTIFY)
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh create /cluster/notifications/endpoints/webhook",
        "pvesh create /cluster/notifications/matchers",
        "pvesh create /cluster/notifications/targets/hnx-notify-hv-a/test",
        "pvesh set /cluster/notifications/matchers/default-matcher",
    ]
    assert calls[-1].endswith("--disable 1")


def test_a_failed_test_leaves_the_mail_matcher_on(node, tmp_path):
    run = node(NOTIFY)
    Path(f"{tmp_path / 'state'}.testfail").touch()
    r, calls = run()
    assert r.returncode != 0
    assert not any("default-matcher" in c for c in calls)


def test_a_rerun_updates_in_place(node):
    run = node(NOTIFY)
    run()
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh set /cluster/notifications/endpoints/webhook/hnx-notify-hv-a",
        "pvesh set /cluster/notifications/matchers/hnx-notify-hv-a-route",
        "pvesh create /cluster/notifications/targets/hnx-notify-hv-a/test",
        "pvesh set /cluster/notifications/matchers/default-matcher",
    ]


def test_default_mail_leaves_the_built_in_matcher_alone_on_apply(node):
    run = node({**NOTIFY, "default_mail": True})
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert not any("default-matcher" in c for c in calls)


def test_remove_turns_mail_on_whatever_default_mail_says_now(node, tmp_path):
    # applied with mail off, then the entry edited to default_mail: true and re-rendered:
    # the new script's --remove must still turn the mail matcher back on
    node(NOTIFY)()
    r, calls = node({**NOTIFY, "default_mail": True})("--remove")
    assert r.returncode == 0, r.stderr
    assert _verbs(calls)[0] == "pvesh set /cluster/notifications/matchers/default-matcher"
    assert next(c for c in calls if "default-matcher" in c).endswith("--delete disable")


def test_the_readme_says_how_to_undo_before_the_key_goes(tmp_path):
    readme = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}}), "node-notify")[
        "notify/README.md"
    ]
    assert "old script's `--remove`" in readme


def test_remove_turns_mail_on_then_takes_the_matcher_off_before_the_target(node):
    run = node(NOTIFY)
    run()
    r, calls = run("--remove")
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh set /cluster/notifications/matchers/default-matcher",
        "pvesh delete /cluster/notifications/matchers/hnx-notify-hv-a-route",
        "pvesh delete /cluster/notifications/endpoints/webhook/hnx-notify-hv-a",
    ]
    assert next(c for c in calls if "default-matcher" in c).endswith("--delete disable")


def test_a_failed_delete_on_remove_leaves_mail_on(node, tmp_path):
    # set -e stops at the failed delete: the mail matcher must already be back on by then
    run = node(NOTIFY)
    run()
    Path(f"{tmp_path / 'state'}.deletefail").touch()
    r, calls = run("--remove")
    assert r.returncode != 0
    verbs = _verbs(calls)
    assert verbs[0] == "pvesh set /cluster/notifications/matchers/default-matcher"
    assert verbs[1].startswith("pvesh delete")
    assert any("default-matcher" in c and c.endswith("--delete disable") for c in calls)


def test_test_sends_through_the_target(node):
    run = node(NOTIFY)
    r, calls = run("--test")
    assert r.returncode == 0 and calls == [
        "pvesh create /cluster/notifications/targets/hnx-notify-hv-a/test"
    ]


@pytest.mark.parametrize("args", [("--yes",), ("--test", "--remove")])
def test_the_script_refuses_bad_arguments(node, args):
    run = node(NOTIFY)
    r, calls = run(*args)
    assert r.returncode == 2 and calls == []


@pytest.mark.parametrize(
    "args",
    [
        ("--match-severity", "warning,crit"),
        ("--match-severity", "warning,,error"),
        ("--match-severity", ""),
        ("--delete", "disable,secret"),
        ("--delete", "bogus"),
    ],
)
def test_the_stub_refuses_what_pvesh_refuses(node, args):
    # the stub is only evidence for the script if it refuses what the real node refuses
    node(NOTIFY)
    r = subprocess.run(
        ["pvesh", "set", "/cluster/notifications/matchers/default-matcher", *args],
        env={
            **os.environ,
            "PATH": f"{node.bin}:{os.environ['PATH']}",
            "LOG": os.devnull,
            "STATE": node.state,
        },
        capture_output=True,
    )
    assert r.returncode == 255


def test_a_rerun_sends_a_comma_joined_severity_list_and_one_key_per_delete(node):
    run = node(NOTIFY)
    run()
    r, calls = run()
    assert r.returncode == 0, r.stderr
    matcher = next(
        c for c in calls if c.startswith("pvesh set /cluster/notifications/matchers/hnx")
    )
    assert "--match-severity warning,error,unknown " in matcher
    assert matcher.count("--delete ") == 3
    target = next(c for c in calls if c.startswith("pvesh set /cluster/notifications/endpoints"))
    assert target.count("--delete ") == 2


# ------------------------------------------------------------------ the publish credential

CRED = {**NOTIFY, "credential": "secret:token"}
#: a stand-in token value (not a real one): the tests prove where it goes and where it never is
VALUE = "tk_standin0123456789abcdef"


def _b64s(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _prop(call: str, flag: str) -> list[str]:
    parts = call.split()
    return [parts[i + 1] for i, p in enumerate(parts[:-1]) if p == flag]


def test_a_credential_loads_as_its_name(tmp_path):
    got = load_nodes(nodes_file(tmp_path, {"hv-a": {"notify": CRED}}))["hv-a"]["notify"]
    assert got["credential"] == "token"


def test_a_bad_credential_is_refused_without_echoing_it(tmp_path):
    with pytest.raises(ComputeError) as ei:
        load_nodes(nodes_file(tmp_path, {"hv-a": {"notify": {**NOTIFY, "credential": VALUE}}}))
    assert VALUE not in str(ei.value)


def test_no_credential_renders_no_auth(tmp_path):
    sh = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}}), "node-notify")[
        "notify/hv-a/hnx-notify.sh"
    ]
    assert "Authorization" not in sh and "--secret" not in sh and node_notify.SECRET_ENV not in sh


def test_the_rendered_credential_is_a_name_and_a_template_never_a_value(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"notify": CRED}}), "node-notify")
    sh = out["notify/hv-a/hnx-notify.sh"]
    assert 'SECRET_NAME="token"' in sh
    assert f'AUTH="{_b64s("Bearer {{ secrets.token }}")}"' in sh
    assert "| `secret:token` |" in out["notify/README.md"]


@pytest.mark.parametrize("how", ["env", "stdin"])
def test_the_first_run_stores_the_secret_and_sends_the_bearer_header(node, how):
    run = node(CRED)
    given = {"extra_env": {node_notify.SECRET_ENV: VALUE}} if how == "env" else {"stdin": VALUE}
    r, calls = run(**given)
    assert r.returncode == 0, r.stderr
    create = next(c for c in calls if c.startswith("pvesh create /cluster/notifications/endpoints"))
    assert _prop(create, "--header") == [
        f"name=Content-Type,value={_b64s('application/json')}",
        f"name=Authorization,value={_b64s('Bearer {{ secrets.token }}')}",
    ]
    assert _prop(create, "--secret") == [f"name=token,value={_b64s(VALUE)}"]
    # the value is never in the rendered script, and pvesh gets it only base64-encoded
    assert VALUE not in run.script.read_text() and _b64s(VALUE) not in run.script.read_text()
    assert not any(VALUE in c for c in calls)
    assert _verbs(calls)[-1] == "pvesh set /cluster/notifications/matchers/default-matcher"


def test_a_rerun_converges_headers_and_secret_and_never_deletes_the_secret(node):
    run = node(CRED)
    run(extra_env={node_notify.SECRET_ENV: VALUE})
    r, calls = run(extra_env={node_notify.SECRET_ENV: VALUE + "x"})
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh set /cluster/notifications/endpoints/webhook/hnx-notify-hv-a",
        "pvesh set /cluster/notifications/matchers/hnx-notify-hv-a-route",
        "pvesh create /cluster/notifications/targets/hnx-notify-hv-a/test",
        "pvesh set /cluster/notifications/matchers/default-matcher",
    ]
    target = next(c for c in calls if c.startswith("pvesh set /cluster/notifications/endpoints"))
    assert _prop(target, "--delete") == ["disable"]  # never --delete secret
    assert _prop(target, "--secret") == [f"name=token,value={_b64s(VALUE + 'x')}"]  # rotated
    assert len(_prop(target, "--header")) == 2
    state = Path(f"{node.state}_cluster_notifications_endpoints_webhook_hnx-notify-hv-a")
    assert "name=Authorization" in state.read_text()


@pytest.mark.parametrize("value", [None, "", "two words", "tab\there"])
def test_no_usable_credential_changes_nothing(node, value):
    run = node(CRED)
    extra = {} if value is None else {node_notify.SECRET_ENV: value}
    r, calls = run(extra_env=extra)
    assert r.returncode == 2 and calls == []
    assert "publish credential" in r.stderr
    if value:
        assert value not in r.stderr


def test_test_and_remove_need_no_credential(node):
    run = node(CRED)
    run(extra_env={node_notify.SECRET_ENV: VALUE})
    r, calls = run("--test")
    assert r.returncode == 0 and len(calls) == 1
    r, calls = run("--remove")
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh set /cluster/notifications/matchers/default-matcher",
        "pvesh delete /cluster/notifications/matchers/hnx-notify-hv-a-route",
        "pvesh delete /cluster/notifications/endpoints/webhook/hnx-notify-hv-a",
    ]


def test_dropping_the_credential_removes_the_secret_on_the_next_apply(node):
    node(CRED)(extra_env={node_notify.SECRET_ENV: VALUE})
    r, calls = node(NOTIFY)()
    assert r.returncode == 0, r.stderr
    target = next(c for c in calls if c.startswith("pvesh set /cluster/notifications/endpoints"))
    assert _prop(target, "--delete") == ["disable", "secret"]
    assert "Authorization" not in target


def test_a_hand_applied_target_is_adopted_unchanged(tmp_path):
    """The shape a node configured by hand already has: target hnx-notify-<node>, the server's
    root URL, its topic, Authorization: Bearer {{ secrets.token }}, secret token."""
    spec = {"url": "http://192.0.2.10", "topic": "hv-alerts", "credential": "secret:token"}
    sh = render(fleet_with(tmp_path, {"hv-a": {"notify": spec}}), "node-notify")[
        "notify/hv-a/hnx-notify.sh"
    ]
    assert 'NAME="hnx-notify-hv-a"' in sh and 'URL="http://192.0.2.10/"' in sh
    line = next(x for x in sh.splitlines() if x.startswith('AUTH="'))
    assert base64.b64decode(line[len('AUTH="') : -1]).decode() == "Bearer {{ secrets.token }}"
    assert 'SECRET_NAME="token"' in sh
    body_line = next(x for x in sh.splitlines() if x.startswith('BODY="'))
    assert '"topic":"hv-alerts"' in base64.b64decode(body_line[len('BODY="') : -1]).decode()


@pytest.mark.requires_tool("shellcheck")
def test_the_credential_script_passes_shellcheck(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"notify": CRED}}), "node-notify")
    script = tmp_path / "hnx-notify.sh"
    script.write_text(out["notify/hv-a/hnx-notify.sh"], encoding="utf-8")
    subprocess.run(["shellcheck", "-s", "sh", str(script)], check=True)
