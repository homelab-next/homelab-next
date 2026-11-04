# SPDX-License-Identifier: Apache-2.0
"""tools/pin_freshness.py: finds the pins dependabot cannot parse, compares them with upstream
past the cooldown, and never fails for being behind.  Every upstream answer here is a fixture;
nothing reaches the network."""

from __future__ import annotations

import email.message
import io
import json
import sys
import urllib.error
import urllib.request
import urllib.response
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import pin_freshness as pf

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def ago(days: float) -> str:
    return (NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")


# --- fixtures: a small tree and the upstream answers ----------------------------------------


def make_tree(root: Path) -> Path:
    files = {
        "ansible/roles/agent/defaults/main.yml": (
            '# SPDX-License-Identifier: Apache-2.0\n---\nagent_version: "1.2.3"\nagent_port: 8080\n'
        ),
        "ansible/roles/scanner/defaults/main.yml": 'scanner_version: ""  # what the repo serves\n',
        "ansible/roles/webui/defaults/main.yml": (
            'webui_image: "ghcr.io/example/webui:v0.4.1@sha256:' + "a" * 64 + '"\n'
        ),
        ".github/workflows/ci.yml": (
            "env:\n"
            '  GO_VERSION: "1.26.9"\n'
            "jobs:\n"
            "  tools:\n"
            "    env:\n"
            '      LINTER_VERSION: "v1.7.11"\n'
            '      LINTER_SUM_SHA256: "' + "b" * 64 + '"\n'
            "    steps:\n"
            "      - uses: actions/setup-python@" + "c" * 40 + "  # v7.0.0\n"
            "        with:\n"
            '          python-version: "3.12"\n'
        ),
        "homelabnext/compute/gen/terraform_proxmox.py": (
            'P = """\n    proxmox = {\n      source  = "bpg/proxmox"\n      version = "~> 0.60"\n'
            '    }\n"""\n'
        ),
        "Makefile": "constraints:\n\tuv pip compile pyproject.toml -o constraints/ci.txt\n",
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


SOURCES = {
    "role:agent/agent_version": ("github", "example/agent"),
    "role:scanner/scanner_version": ("github", "example/scanner"),
    "role:webui/webui_image": ("github", "example/webui"),
    "ci:GO_VERSION": ("go-toolchain", ""),
    "ci:LINTER_VERSION": ("pypi", "linter"),
    "terraform:bpg/proxmox": ("github", "bpg/terraform-provider-proxmox"),
    "tool:uv": ("none", "not compared in this fixture"),
}


def gh(*releases: tuple[str, float, dict]) -> list[dict]:
    return [
        {"tag_name": t, "published_at": ago(d), "draft": False, "prerelease": False, **extra}
        for t, d, extra in releases
    ]


UPSTREAM = {
    "https://api.github.com/repos/example/agent/releases?per_page=100": gh(
        ("v1.2.3", 90, {}),
        ("v1.2.4", 30, {}),  # same line, past the cooldown
        ("v1.3.0", 20, {}),  # newest past the cooldown
        ("v1.4.0", 3, {}),  # held: inside the cooldown
        ("v2.0.0-rc1", 40, {}),  # a pre-release by name
        ("v1.9.0", 40, {"draft": True}),
        ("v1.8.0", 40, {"prerelease": True}),
        ("nightly", 1, {}),
    ),
    "https://api.github.com/repos/example/scanner/releases?per_page=100": gh(("v0.76.1", 30, {})),
    "https://api.github.com/repos/example/webui/releases?per_page=100": gh(
        ("v0.4.1", 60, {}), ("v0.5.0", 15, {}), ("v0.6.0", 2, {})
    ),
    "https://api.github.com/repos/bpg/terraform-provider-proxmox/releases?per_page=100": gh(
        ("v0.60.0", 400, {}), ("v0.120.0", 30, {})
    ),
    "https://pypi.org/pypi/linter/json": {
        "releases": {
            "1.7.11": [{"upload_time_iso_8601": ago(100), "yanked": False}],
            "1.7.12": [{"upload_time_iso_8601": ago(50), "yanked": False}],
            "1.7.13": [{"upload_time_iso_8601": ago(20), "yanked": True}],  # yanked
            "1.8.0rc1": [{"upload_time_iso_8601": ago(20), "yanked": False}],
            "1.8.0": [],  # no files
        }
    },
    "https://proxy.golang.org/golang.org/toolchain/@v/list": (
        "v0.0.1-go1.26.9.linux-amd64\nv0.0.1-go1.26.10.linux-amd64\nv0.0.1-go1.26.10.darwin-arm64\n"
        "v0.0.1-go1.27.3.linux-amd64\nv0.0.1-go1.27rc1.linux-amd64\n"
    ),
    "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.26.9.linux-amd64.info": {
        "Time": ago(33)
    },
    "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.26.10.linux-amd64.info": {
        "Time": ago(16)
    },
    "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.27.3.linux-amd64.info": {
        "Time": ago(16)
    },
}


class FakeUpstream:
    def __init__(self, answers: dict, fail: tuple[str, ...] = ()):
        self.answers, self.fail, self.calls = answers, fail, []

    def __call__(self, url: str):
        self.calls.append(url)
        if any(url.startswith(f) for f in self.fail):
            raise OSError("upstream unreachable")
        return self.answers[url]


# --- inventory ---------------------------------------------------------------------------


def test_inventory_finds_every_kind_of_pin_with_its_place(tmp_path):
    pins = {p.id: p for p in pf.inventory(make_tree(tmp_path))}
    assert sorted(pins) == sorted(SOURCES)
    assert pins["role:agent/agent_version"] == pf.Pin(
        "role:agent/agent_version", "ansible/roles/agent/defaults/main.yml", 3, "1.2.3"
    )
    assert pins["role:scanner/scanner_version"].kind == "unpinned"
    assert pins["role:webui/webui_image"].kind == "image"
    assert pins["ci:GO_VERSION"].checksum is None
    assert pins["ci:LINTER_VERSION"].checksum == "LINTER_SUM_SHA256"
    assert pins["ci:LINTER_VERSION"].line == 6
    tf = pins["terraform:bpg/proxmox"]
    assert (tf.value, tf.kind, tf.line) == ("~> 0.60", "constraint", 4)
    assert pins["tool:uv"] == pf.Pin("tool:uv", "Makefile", 2, "", kind="unpinned")


def test_every_pin_in_this_tree_has_an_upstream():
    """A new pin dependabot cannot see must name where its releases are, or nothing watches it."""
    assert pf.check_inventory(pf.inventory(ROOT)) == []


def test_the_inventory_check_names_a_missing_and_a_stale_source(tmp_path):
    pins = pf.inventory(make_tree(tmp_path))
    sources = {k: v for k, v in SOURCES.items() if k != "tool:uv"} | {"ci:GONE": ("pypi", "x")}
    assert pf.check_inventory(pins, sources) == [
        "Makefile:2: tool:uv has no upstream in SOURCES",
        "SOURCES names ci:GONE, which the tree no longer pins",
    ]


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("1.26.10", (1, 26, 10)),
        ("v1.7.12", (1, 7, 12)),
        ("484", (484,)),
        ("v2.0.0-rc1", None),
        ("1.8.0rc1", None),
        ("~> 0.60", None),
        ("", None),
        ("nightly", None),
    ],
)
def test_parse_version(text, want):
    assert pf.parse_version(text) == want


# --- upstream ----------------------------------------------------------------------------


def test_github_releases_skip_drafts_prereleases_and_non_versions():
    got = pf.releases(("github", "example/agent"), FakeUpstream(UPSTREAM))
    assert [r.tag for r in got] == ["v1.2.3", "v1.2.4", "v1.3.0", "v1.4.0"]


def test_pypi_releases_skip_yanked_fileless_and_pre_releases():
    got = pf.releases(("pypi", "linter"), FakeUpstream(UPSTREAM))
    assert [r.tag for r in got] == ["1.7.11", "1.7.12"]


def test_go_toolchain_releases_are_the_linux_builds_dated_by_the_proxy():
    fetch = FakeUpstream(UPSTREAM)
    got = pf.releases(("go-toolchain", ""), fetch)
    assert [r.tag for r in got] == ["1.26.9", "1.26.10", "1.27.3"]
    assert got[-1].published == NOW - timedelta(days=16)


# --- assessment --------------------------------------------------------------------------


def rel(tag: str, days: float) -> pf.Release:
    return pf.Release(pf.parse_version(tag), tag, NOW - timedelta(days=days))


@pytest.mark.parametrize(
    ("value", "kind", "rels", "status"),
    [
        ("1.2.3", "version", [rel("1.2.3", 90), rel("1.2.4", 20)], "behind (patch)"),
        ("1.2.3", "version", [rel("1.3.0", 20)], "behind (minor)"),
        ("1.2.3", "version", [rel("2.0.0", 20)], "behind (major)"),
        ("0.31.0", "version", [rel("0.32.0", 20)], "behind (0.x minor)"),
        ("0.31.0", "version", [rel("0.31.1", 20)], "behind (patch)"),
        ("1.2.3", "version", [rel("1.2.3", 90), rel("1.2.4", 13)], "current"),  # held back
        ("1.2.3", "version", [], "current"),
        ("", "unpinned", [rel("0.76.1", 30)], "unpinned"),
        ("~> 0.60", "constraint", [rel("0.120.0", 30)], "loose constraint"),
        ("~> 0.120.0", "constraint", [rel("0.120.1", 30)], "behind (patch)"),
        ("latest", "version", [rel("1.0.0", 30)], "unreadable pin"),
    ],
)
def test_assess(value, kind, rels, status):
    f = pf.assess(pf.Pin("x", "p", 1, value, kind=kind), rels, NOW)
    assert f.status == status


def test_the_cooldown_holds_a_young_release_back_and_lists_it():
    rels = [rel("1.2.3", 90), rel("1.2.4", 30), rel("1.3.0", 20), rel("1.4.0", 3)]
    f = pf.assess(pf.Pin("x", "p", 1, "1.2.3"), rels, NOW)
    assert (f.line_latest.tag, f.newest.tag, [r.tag for r in f.held]) == (
        "1.2.4",
        "1.3.0",
        ["1.4.0"],
    )
    # exactly at the boundary a release is past the cooldown; a minute short it is not
    edge = [rel("1.2.3", 90), pf.Release((1, 2, 4), "1.2.4", NOW - timedelta(days=14))]
    assert pf.assess(pf.Pin("x", "p", 1, "1.2.3"), edge, NOW).status == "behind (patch)"
    short = [
        rel("1.2.3", 90),
        pf.Release((1, 2, 4), "1.2.4", NOW - timedelta(days=14) + timedelta(minutes=1)),
    ]
    assert pf.assess(pf.Pin("x", "p", 1, "1.2.3"), short, NOW).status == "current"
    assert (
        pf.assess(pf.Pin("x", "p", 1, "1.2.3"), short, NOW, cooldown=0).status == "behind (patch)"
    )


def test_an_image_pin_is_judged_by_its_tag():
    image = "ghcr.io/example/webui:v0.4.1@sha256:" + "a" * 64
    assert pf.current_version(pf.Pin("x", "p", 1, image, kind="image")) == (0, 4, 1)


def test_build_reads_each_upstream_once_and_reports_an_unreadable_one(tmp_path):
    pins = pf.inventory(make_tree(tmp_path))
    pins.append(pf.Pin("role:agent/agent_version_copy", "p", 1, "1.2.3"))
    sources = SOURCES | {"role:agent/agent_version_copy": SOURCES["role:agent/agent_version"]}
    fetch = FakeUpstream(UPSTREAM, fail=("https://api.github.com/repos/example/scanner",
                                         "https://api.github.com/repos/bpg/"))  # fmt: skip
    found = {f.pin.id: f for f in pf.build(pins, fetch, NOW, sources=sources)}
    assert (
        fetch.calls.count("https://api.github.com/repos/example/agent/releases?per_page=100") == 1
    )
    assert found["role:agent/agent_version"].status == "behind (minor)"
    assert found["role:webui/webui_image"].status == "behind (0.x minor)"
    assert found["ci:GO_VERSION"].status == "behind (minor)"
    assert found["ci:GO_VERSION"].line_latest.tag == "1.26.10"
    assert found["ci:LINTER_VERSION"].status == "behind (patch)"
    # an unreadable upstream: an unpinned item stays unpinned, a loose one loose, with the error
    assert found["role:scanner/scanner_version"].status == "unpinned"
    assert "upstream unreachable" in found["role:scanner/scanner_version"].error
    assert found["terraform:bpg/proxmox"].status == "loose constraint"
    assert found["tool:uv"].status == "not compared"


def test_an_unreadable_upstream_of_a_version_is_not_checked_rather_than_current():
    pin = pf.Pin("role:agent/agent_version", "p", 1, "1.2.3")
    (f,) = pf.build([pin], FakeUpstream({}, fail=("https://",)), NOW, sources=SOURCES)
    assert f.status == "not checked" and f.error


# --- report and command line -------------------------------------------------------------


def test_the_report_starts_with_the_marker_and_names_each_pin_where_it_is(tmp_path):
    pins = pf.inventory(make_tree(tmp_path))
    text = pf.render(pf.build(pins, FakeUpstream(UPSTREAM), NOW, sources=SOURCES), NOW)
    assert text.startswith(pf.MARKER + "\n")
    assert "`ci:LINTER_VERSION` | `.github/workflows/ci.yml:6` | `v1.7.11` | behind (patch)" in text
    assert "bump `LINTER_SUM_SHA256` with it" in text
    assert "`ghcr.io/example/webui:v0.4.1@sha256:aaaaaaaaaaaa…`" in text
    assert "v1.4.0" in text  # held, listed
    rows = [line for line in text.splitlines() if line.startswith("| `")]
    assert len(rows) == len(pins)
    assert rows[0].startswith("| `role:webui/webui_image`")  # the most urgent first


def test_main_writes_the_report_and_exits_zero_although_pins_are_behind(tmp_path, monkeypatch):
    monkeypatch.setattr(pf, "SOURCES", SOURCES)
    root = make_tree(tmp_path / "tree")
    out = tmp_path / "pins.md"
    rc = pf.main(
        ["report", "--out", str(out), "--now", "2026-11-04T12:00:00Z"],
        fetch=FakeUpstream(UPSTREAM),
        root=root,
    )
    assert rc == 0 and "behind (minor)" in out.read_text()


def test_main_takes_an_injected_now(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pf, "SOURCES", SOURCES)
    root = make_tree(tmp_path)
    assert pf.main(["report"], fetch=FakeUpstream(UPSTREAM), root=root, now=NOW) == 0
    assert "Generated 2026-11-04 12:00 UTC" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv", [["report", "--now", "yesterday"], ["report", "--cooldown-days", "-1"]]
)
def test_main_refuses_bad_arguments(tmp_path, argv):
    assert pf.main(argv, fetch=FakeUpstream({}), root=make_tree(tmp_path), now=NOW) == 2


def test_inventory_check_exit_status(tmp_path, monkeypatch, capsys):
    root = make_tree(tmp_path)
    monkeypatch.setattr(pf, "SOURCES", SOURCES)
    assert pf.main(["inventory", "--check"], root=root) == 0
    assert {p["id"] for p in json.loads(capsys.readouterr().out)} == set(SOURCES)
    monkeypatch.setattr(pf, "SOURCES", {k: v for k, v in SOURCES.items() if k != "tool:uv"})
    assert pf.main(["inventory", "--check"], root=root) == 1
    assert "tool:uv has no upstream" in capsys.readouterr().err


class FakeHTTPS(urllib.request.HTTPSHandler):
    """Answers https requests from a table instead of the network: url -> (status, headers, body),
    and records every request it was given."""

    def __init__(self, table: dict[str, tuple[int, dict[str, str], bytes]]):
        super().__init__()
        self.table, self.seen = table, []

    def https_open(self, req):
        self.seen.append(req)
        status, headers, body = self.table[req.full_url]
        msg = email.message.Message()
        for k, v in headers.items():
            msg[k] = v
        resp = urllib.response.addinfourl(io.BytesIO(body), msg, req.full_url, status)
        resp.msg = "fixture"  # the reason phrase urllib's error processor reads
        return resp


JSON = {"Content-Type": "application/json; charset=utf-8"}


def fetch_with(table, url, monkeypatch, token="fixture-token"):
    if token:
        monkeypatch.setenv("GH_TOKEN", token)
    fake = FakeHTTPS(table)
    return pf.http_fetch(url, pf.opener(fake)), fake


@pytest.mark.parametrize(
    ("url", "authorised"),
    [
        ("https://api.github.com/repos/o/r/releases?per_page=100", True),
        ("https://pypi.org/pypi/x/json", False),
        ("https://api.github.com.example.test/repos", False),
    ],
)
def test_the_token_goes_to_the_github_api_only(monkeypatch, url, authorised):
    got, fake = fetch_with({url: (200, JSON, b'{"ok": true}')}, url, monkeypatch)
    assert got == {"ok": True}
    assert fake.seen[0].has_header("Authorization") is authorised


def test_a_redirect_to_another_host_drops_the_token(monkeypatch):
    start = "https://api.github.com/repos/o/r/releases?per_page=100"
    moved = "https://api.github.com/repositories/1/releases?per_page=100"
    away = "https://objects.example.test/releases.json"
    table = {
        start: (301, {"Location": moved}, b""),
        moved: (302, {"Location": away}, b""),
        away: (200, JSON, b"[]"),
    }
    got, fake = fetch_with(table, start, monkeypatch)
    assert got == []
    assert [r.full_url for r in fake.seen] == [start, moved, away]
    assert [r.has_header("Authorization") for r in fake.seen] == [True, True, False]


def test_a_redirect_away_from_https_is_refused(monkeypatch):
    start = "https://api.github.com/repos/o/r/releases?per_page=100"
    table = {start: (302, {"Location": "http://api.github.com/x"}, b"")}
    with pytest.raises(urllib.error.HTTPError, match="away from https"):
        fetch_with(table, start, monkeypatch)


def test_an_oversized_answer_is_refused(monkeypatch):
    monkeypatch.setattr(pf, "MAX_BYTES", 10)
    url = "https://pypi.org/pypi/x/json"
    assert fetch_with({url: (200, JSON, b'"0123456"')}, url, monkeypatch, token="")[0] == "0123456"
    with pytest.raises(ValueError, match="larger than"):
        fetch_with({url: (200, JSON, b'"0123456789"')}, url, monkeypatch, token="")


HOSTILE = (
    "see @octocat <img src=x onerror=y> [click](https://evil.example.test) `code` | col\n" * 20
)


def test_an_upstream_error_reaches_the_issue_short_and_inert():
    pin = pf.Pin("role:agent/agent_version", "p", 1, "1.2.3")

    def fetch(url):
        raise ValueError(HOSTILE)

    (f,) = pf.build([pin], fetch, NOW, sources=SOURCES)
    assert f.status == "not checked"
    assert len(f.error) <= pf.MAX_ERROR + len("ValueError: ")
    assert not set("`|<>[]@\n") & set(f.error)
    row = next(x for x in pf.render([f], NOW).splitlines() if x.startswith("| `role:"))
    note = row.rsplit(" | ", 1)[1]
    assert note.startswith("`ValueError: ") and note.count("`") == 2  # one inert code span


def test_an_http_error_is_its_type_and_status_only():
    exc = urllib.error.HTTPError("https://x", 403, "<b>@admin</b>", None, None)
    assert pf.describe(exc) == "HTTPError 403"


def test_an_unreadable_tree_or_out_file_is_exit_2(tmp_path):
    root = make_tree(tmp_path / "t")
    bad = root / "ansible/roles/agent/defaults/main.yml"
    bad.write_bytes(b"agent_version: \xff\xfe\n")
    assert pf.main(["inventory"], root=root) == 2
    root = make_tree(tmp_path / "u")
    out = tmp_path / "missing-dir" / "pins.md"
    rc = pf.main(
        ["report", "--out", str(out)],
        fetch=FakeUpstream({}, fail=("https://",)),
        root=root,
        now=NOW,
    )
    assert rc == 2


# --- the workflow ------------------------------------------------------------------------

WORKFLOWS = ROOT / ".github" / "workflows"


def test_the_workflow_is_scheduled_least_privileged_and_never_on_a_pull_request():
    wf = yaml.safe_load((WORKFLOWS / "pin-freshness.yml").read_text())
    on = wf[True] if True in wf else wf["on"]  # YAML 1.1 reads a bare `on` as true
    assert set(on) == {"schedule", "workflow_dispatch"}
    assert wf["permissions"] == {}
    (job,) = wf["jobs"].values()
    assert job["permissions"] == {"contents": "read", "issues": "write"}
    assert "default_branch" in job["if"]
    text = (WORKFLOWS / "pin-freshness.yml").read_text()
    assert f'startswith("{pf.MARKER}")' in text  # the issue is found by the report's marker


def test_no_other_workflow_runs_the_network_report():
    others = [p.name for p in WORKFLOWS.glob("*.yml") if p.name != "pin-freshness.yml"]
    assert others and not [
        n for n in others if "pin_freshness.py report" in (WORKFLOWS / n).read_text()
    ]
