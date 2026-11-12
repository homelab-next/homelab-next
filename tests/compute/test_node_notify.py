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
        ({**NOTIFY, "topic": "a/b"}, "not a topic"),
        ({**NOTIFY, "topic": "a" * 65}, "not a topic"),
        ({**NOTIFY, "severities": []}, "non-empty list"),
        ({**NOTIFY, "severities": ["critical"]}, "non-empty list"),
        ({**NOTIFY, "severities": ["error", "error"]}, "listed twice"),
        ({**NOTIFY, "priority": 6}, "1 to 5"),
        ({**NOTIFY, "priority": True}, "1 to 5"),
        ({**NOTIFY, "default_mail": "no"}, "true or false"),
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
        "| `warning`, `error`, `unknown` | turned off |" in out["notify/README.md"]
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


def test_the_target_and_the_matcher_have_different_names():
    # one namespace for both in notifications.cfg: creating the second would fail
    assert node_notify.NAME != node_notify.MATCHER


@pytest.mark.requires_tool("shellcheck")
def test_the_script_passes_shellcheck(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"notify": NOTIFY}}), "node-notify")
    script = tmp_path / "hnx-notify.sh"
    script.write_text(out["notify/hv-a/hnx-notify.sh"], encoding="utf-8")
    subprocess.run(["shellcheck", "-s", "sh", str(script)], check=True)


# ------------------------------------------------------- the script against a fake pvesh
# Each config entry is a file named after its API path; ``create`` refuses a name any target or
# matcher already has (they share one namespace in notifications.cfg), ``set`` and ``delete`` need
# the entry to exist (the built-in default-matcher is seeded), and ``--delete`` takes one key per
# flag (pvesh 9 refuses ``--delete a,b``: "invalid configuration ID 'a,b'").
PVESH_STUB = r"""#!/bin/sh
echo "pvesh $*" >> "$LOG"
verb="$1" path="$2"; shift 2
f="$STATE$(printf '%s' "$path" | tr / _)"
case "$verb" in
  get) [ -e "$f" ] ;;
  create)
    case "$path" in */test) exit 0 ;; esac
    name=""
    while [ "$#" -gt 0 ]; do [ "$1" = --name ] && name="$2"; shift; done
    for e in "$STATE"*_"$name"; do
      [ -e "$e" ] && { echo "an entity with the same name already exists" >&2; exit 255; }
    done
    touch "$f"_"$name" ;;
  set)
    [ -e "$f" ] || { echo "not found" >&2; exit 255; }
    while [ "$#" -gt 0 ]; do
      case "$1" in --delete) case "$2" in *,*) echo "invalid configuration ID" >&2; exit 255 ;; esac ;; esac
      shift
    done ;;
  delete) rm "$f" ;;
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

        def run(*args: str):
            log.write_text("")
            r = subprocess.run(["sh", str(script), *args], env=env, capture_output=True, text=True)
            return r, log.read_text().splitlines()

        return run

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
        "pvesh set /cluster/notifications/matchers/default-matcher",
    ]
    assert calls[-1].endswith("--disable 1")


def test_a_rerun_updates_in_place(node):
    run = node(NOTIFY)
    run()
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh set /cluster/notifications/endpoints/webhook/hnx-notify",
        "pvesh set /cluster/notifications/matchers/hnx-notify-route",
        "pvesh set /cluster/notifications/matchers/default-matcher",
    ]


def test_default_mail_leaves_the_built_in_matcher_alone(node):
    run = node({**NOTIFY, "default_mail": True})
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert not any("default-matcher" in c for c in calls)
    r, calls = run("--remove")
    assert not any("default-matcher" in c for c in calls)


def test_remove_takes_the_matcher_off_before_the_target(node):
    run = node(NOTIFY)
    run()
    r, calls = run("--remove")
    assert r.returncode == 0, r.stderr
    assert _verbs(calls) == [
        "pvesh delete /cluster/notifications/matchers/hnx-notify-route",
        "pvesh delete /cluster/notifications/endpoints/webhook/hnx-notify",
        "pvesh set /cluster/notifications/matchers/default-matcher",
    ]
    assert calls[-1].endswith("--delete disable")


def test_test_sends_through_the_target(node):
    run = node(NOTIFY)
    r, calls = run("--test")
    assert r.returncode == 0 and calls == [
        "pvesh create /cluster/notifications/targets/hnx-notify/test"
    ]


@pytest.mark.parametrize("args", [("--yes",), ("--test", "--remove")])
def test_the_script_refuses_bad_arguments(node, args):
    run = node(NOTIFY)
    r, calls = run(*args)
    assert r.returncode == 2 and calls == []
