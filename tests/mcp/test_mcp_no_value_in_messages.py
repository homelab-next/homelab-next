# SPDX-License-Identifier: Apache-2.0
"""No message of the MCP catalog carries a value (CodeQL: clear-text logging of sensitive data).

Check, render and import print their problems, notes and refusals to stdout and stderr, where CI
logs keep them.  A value from a record, a render spec, a profile or a parameter may be a
credential pasted by mistake (exactly what check is there to catch), so a message names the field
and the rule it broke, a URL only by its scheme and host (userinfo as ``***``), and never the
value.  Every value position below is seeded with one fake secret; it must never be printed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli

ROOT = Path(__file__).resolve().parents[2]
FAKE = "fakesekr3tval9zq7xw2lp5"  # lower case: it can stand in a host name too
COLLECTOR = ROOT / "examples" / "mcp" / "clients" / "profile.collector.json"


def _lab(tmp_path: Path) -> Path:
    """A copy of the example catalog with its registry and a review policy beside it."""
    lab = tmp_path / "lab"
    shutil.copytree(
        ROOT / "examples" / "mcp", lab / "mcp", ignore=shutil.ignore_patterns("clients")
    )
    shutil.copy(ROOT / "examples" / "services.yml", lab)
    shutil.copy(ROOT / "examples" / "review-policy.yml", lab)
    return lab / "mcp"


def _edit(cat: Path, sid: str, change) -> None:
    rec = yaml.safe_load((cat / f"{sid}.yml").read_text())
    change(rec)
    (cat / f"{sid}.yml").write_text(yaml.safe_dump(rec))


def _seed(cat: Path) -> None:
    def notes(r):
        r["transport"]["args"] = ["--api", FAKE, f"--x={FAKE}"]
        r["transport"]["bin"] = "other-mcp"
        r["origin"]["bins"] = [FAKE]  # bin not in bins
        r["origin"].pop("sha256")
        r["origin"]["lock"] = f"locks/{FAKE}.lock"  # a lock path that does not exist
        r["settings"] = {"NOTES_ROOT": FAKE, "NOTES_URL": f"https://u:{FAKE}@h.example.com/x"}
        r["parameters"]["mode"]["default"] = FAKE  # not one of its enum

    _edit(cat, "notes", notes)
    _edit(cat, "cases", lambda r: r["env"].update(CASES_TOKEN=FAKE))
    _edit(cat, "lake", lambda r: (r["headers"].update(Authorization=f"Bearer {FAKE}"),
                                  r["transport"].update(path=f"/{FAKE}")))  # fmt: skip
    _edit(cat, "records", lambda r: r.update(origin={
        "kind": "git", "ecosystem": "pypi", "repo": f"https://fakeuser:{FAKE}@code.example/o/r",
        "commit": None, "bins": ["records-mcp"]}))  # fmt: skip
    _edit(cat, "git", lambda r: r["parameters"].update(
        {"repo": {"env": "GIT_MCP_REPO", "pattern": f"[a-z]+{FAKE}", "default": FAKE + "!"}})
        if r.get("parameters") is not None else r.update(parameters={
            "repo": {"env": "GIT_MCP_REPO", "pattern": f"[a-z+{FAKE}", "default": FAKE}}))  # fmt: skip
    remote = yaml.safe_load((ROOT / "schemas/platform/examples/mcp_server.remote.yml").read_text())
    remote["transport"]["url"] = f"http://user:{FAKE}@mcp.{FAKE}.example.com/x?token={FAKE}"
    (cat / "tracker.yml").write_text(yaml.safe_dump(remote))


def _assert_clean(capsys) -> str:
    out = capsys.readouterr()
    text = out.out + out.err
    assert FAKE not in text and FAKE.upper() not in text, text
    return text


def test_check_names_the_rule_never_the_value(tmp_path, capsys):
    cat = _lab(tmp_path)
    _seed(cat)
    assert cli.main(["mcp", "catalog", "check", "--catalog", str(cat), "--grants"]) == 1
    text = _assert_clean(capsys)
    for phrase in ("argument 2", "bin is not one of the package's reviewed bins",
                   "its lock file does not exist", "setting NOTES_ROOT", "env/CASES_TOKEN",
                   "headers/Authorization", "https://***@code.example", "transport/url",
                   ):  # fmt: skip
        assert phrase in text, phrase


def test_render_names_the_rule_never_the_value(tmp_path, capsys):
    cat = _lab(tmp_path)
    pol = tmp_path / "pol.yml"
    pol.write_text((ROOT / "examples/mcp/clients/policy/ceilings.yml").read_text())
    base = ["mcp", "catalog", "render", "--catalog", str(cat), "--profile", str(COLLECTOR),
            "--client", "claude-code", "--policy", str(pol)]  # fmt: skip
    for extra in (["--param", f"notes.mode={FAKE}"], ["--param", f"notes.writable=/{FAKE}"],
                  ["--param", f"notes.{FAKE}=x"], ["--param", FAKE], ["--lanes", f"{FAKE}-$x"],
                  ["--npm-prefix", f"rel/{FAKE}"], ["--checkout-root", f"/x/$({FAKE})"]):  # fmt: skip
        assert cli.main([*base, *extra]) in (1, 2), extra
        _assert_clean(capsys)
    prof = tmp_path / "p.json"
    doc = json.loads(COLLECTOR.read_text())
    prof.write_text(json.dumps({**doc, "data_tier": FAKE, "mcp": ["notes", FAKE]}))
    assert cli.main([*base[:6], str(prof), *base[7:]]) == 1
    _assert_clean(capsys)
    compiled = tmp_path / "c.json"
    compiled.write_text(json.dumps({"id": "profile:collector", "grants": {"mcp": [FAKE]},
                                    "digest": f"sha256:{FAKE}"}))  # fmt: skip
    assert cli.main([*base[:6], str(compiled), *base[7:]]) == 1
    _assert_clean(capsys)
    spec = tmp_path / "spec.yml"
    spec.write_text(f"client: hermes\nprofiles: [{{file: x}}]\noutputs: [{{path: {FAKE}\n")
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec)]) in (1, 2)
    _assert_clean(capsys)
    spec.write_text(yaml.safe_dump({
        "client": "hermes", "catalog": str(cat), "policy": str(pol), "lanes": ["real"],
        "profiles": [{"file": str(COLLECTOR), "params": {"notes": {"mode": FAKE},
                                                         f"x{FAKE}": {"a": "b"}}}],
        "outputs": [{"path": "o.yaml", "params": {f"notes@{FAKE}": {"mode": "read"}}}]}))  # fmt: skip
    assert cli.main(["mcp", "catalog", "render", "--spec", str(spec)]) in (1, 2)
    _assert_clean(capsys)


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "npx", "args": ["-y", f"--{FAKE}", "@example/x@1.0.0"]},
        {"command": "npx", "args": ["-y", f"git+https://u:{FAKE}@code.example/o/r#x"]},
        {"command": "uvx", "args": ["--from", f"git+https://u:{FAKE}@code.example/o/r@x", "s"]},
        {"command": "uvx", "args": ["--from", f"x[{FAKE}!]==1.0.0", "s"]},
        {"command": "docker", "args": ["run", "-i", f"Bad/{FAKE}@x"]},
        {"command": f"/opt/{FAKE}/npx2", "args": [FAKE]},
        {"command": "npx", "args": ["-y", "-p", "@example/x@1.0.0", f"x{FAKE}", "--token", FAKE]},
        {"command": "hnx", "args": ["invariants", "run", FAKE]},
        {"url": f"https://u:{FAKE}@mcp.example.com/{FAKE}?k={FAKE}",
         "headers": {"Authorization": f"Bearer {FAKE}"}},
        {"command": "npx", "args": ["-y", "@example/x@1.0.0"], "env": {"API": FAKE, "U": f"https://u:{FAKE}@h.example.com"}},
    ],
    ids=lambda e: str(e.get("command") or e.get("url"))[:20],
)  # fmt: skip
def test_import_reports_never_the_value(tmp_path, capsys, entry):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"srv": entry}}))
    assert cli.main(["mcp", "catalog", "import", str(cfg), "--out", str(tmp_path / "o")]) == 0
    _assert_clean(capsys)
    bad = tmp_path / "bad.yaml"
    bad.write_text(f"mcp_servers:\n  srv: {{command: npx, args: [{FAKE}\n")
    assert cli.main(["mcp", "catalog", "import", str(bad), "--out", str(tmp_path / "o")]) == 2
    _assert_clean(capsys)
