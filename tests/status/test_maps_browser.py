# SPDX-License-Identifier: Apache-2.0
"""The interactive maps in a real browser (ADR-0018): ``hnx status render`` writes the static
Topology and Dataflow pages of ``examples/lab-topology`` plus one hostile guest and service, and
``map_smoke.mjs`` drives them in headless Chromium through Playwright for Node: no console
error, no CSP violation, the flow overlay draws arrows, a card fills the detail panel, the filter
highlights and Esc clears, a lane and a group collapse, the hostile names stay text.

Skips (with a registered reason) when Node, its Playwright package or a Chromium build is not
installed.  ``HNX_MAP_SHOTS=DIR`` also saves screenshots there."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from status_helpers import REGISTRY, ROOT, VIEWS

from homelabnext.status.cli import main

LAB = ROOT / "examples" / "lab-topology"
SMOKE = Path(__file__).with_name("map_smoke.mjs")
HOSTILE = '</script><script>window.__pwned=1</script><img src=x onerror="window.__pwned=2">\'"&'
HOSTILE_GUEST = f"""id: guest:evil-1
display_name: '</script><script>window.__pwned=3</script>'
description: '{HOSTILE.replace("'", "''")}'
kind: lxc
provisioning: terraform
placement: {{node: hv-2, vmid: 199}}
resources:
  cpu: {{cores: 1}}
  memory: {{size_mb: 512}}
  disks: [{{name: rootfs, size_gb: 4, pool: fast}}]
image: {{logical: debian-12-standard, kind: tarball, os_type: debian}}
network: {{zone: edge, ip: 198.51.100.20}}
capability: cap:context
owners: {{primary: platform-team}}
"""


def _node() -> tuple[str, dict[str, str]]:
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    env = dict(os.environ)
    global_modules = Path(node).resolve().parents[1] / "lib" / "node_modules"
    env["NODE_PATH"] = os.pathsep.join(p for p in (env.get("NODE_PATH"), str(global_modules)) if p)
    if "PLAYWRIGHT_BROWSERS_PATH" not in env and Path("/opt/pw-browsers").is_dir():
        env["PLAYWRIGHT_BROWSERS_PATH"] = "/opt/pw-browsers"
    return node, env


def _site(tmp_path: Path) -> Path:
    lab = tmp_path / "lab"
    shutil.copytree(LAB, lab)
    (lab / "guests" / "evil-1.yml").write_text(HOSTILE_GUEST, encoding="utf-8")
    services = (lab / "services.yml").read_text(encoding="utf-8")
    services = services.replace(
        "  proxy-1:   {address: 198.51.100.10, zone: edge,     role: edge}\n",
        "  proxy-1:   {address: 198.51.100.10, zone: edge,     role: edge}\n"
        "  evil-1:    {address: 198.51.100.20, zone: edge}\n",
    )
    services += (
        "  evil:\n    capability: context\n    host: evil-1\n    protocol: http\n    port: 80\n"
        '    owner: platform-team\n    version: "1.0"\n    tls: none\n    upstreams: [idp]\n'
        f"    description: '{HOSTILE.replace(chr(39), chr(39) * 2)}'\n"
    )
    (lab / "services.yml").write_text(services, encoding="utf-8")
    out = tmp_path / "site"
    args = ["render", "--out", str(out), "--registry", str(REGISTRY), "--views", str(VIEWS),
            "--state", str(tmp_path / "s.json"), "--now", "2026-10-21T00:00:00Z",
            "--guests", str(lab / "guests"), "--guests-site", str(lab / "site.yml"),
            "--guests-registry", str(lab / "services.yml"), "--maps", str(ROOT)]  # fmt: skip
    assert main(args) == 0
    return out


def test_the_interactive_maps_in_a_browser(tmp_path, capsys):
    node, env = _node()
    probe = subprocess.run(
        [node, "-e", "require.resolve('playwright')"], env=env, capture_output=True, timeout=60
    )
    if probe.returncode:
        pytest.skip("playwright for node not installed")
    out = _site(tmp_path)
    capsys.readouterr()
    shots = os.environ.get("HNX_MAP_SHOTS")
    cmd = [node, str(SMOKE), str(out / "topology.html"), str(out / "dataflow.html"),
           "guest:evil-1", *([shots] if shots else [])]  # fmt: skip
    run = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
    assert run.returncode == 0, run.stderr
    got = json.loads(run.stdout.strip().splitlines()[-1])
    if "skip" in got:
        pytest.skip(got["skip"])
    t, d = got["topology"], got["dataflow"]
    assert t["errors"] == [] and t["csp"] == [], (t["errors"], t["csp"])
    assert d["errors"] == [] and d["csp"] == [], (d["errors"], d["csp"])
    # topology: flows toggle, detail panel, highlight, tooltip
    assert t["cards"] >= 20 and t["arrowsBefore"] == 0
    assert t["arrowsOn"] > 15 and t["plannedArrows"] >= 1 and "Hide" in t["toggleText"]
    assert t["panelOpen"] == 1 and t["panelTitle"] == "siem-1" and t["flowItems"] > 3
    assert "What it does" in t["panelText"] and "svc:detections" in t["panelText"]
    assert t["highlighted"] > 0 and t["flowDimmed"] > 0 and "192.0.2.70" in t["tooltip"]
    # hostile names arrive as text and run nothing
    assert HOSTILE in t["hostileText"] and t["hostileImgs"] == 0 and t["pwned"] is None
    assert "evil-1" in t["hostileTip"]
    assert t["panelClosed"]
    # filter (Ctrl+F focuses it, Esc clears), collapse, zoom, theme
    assert t["focused"] == "filter-input" and t["filterHits"] >= 1 and t["filterDimmed"] > 10
    assert t["afterEsc"] == 0
    assert t["laneCollapsed"] == 1 and t["laneExpanded"] == "false"
    assert t["zoomed"] and t["theme"] == "light"
    # dataflow: filter, state filter, collapse, hostile text
    assert d["rows"] > 20 and 0 < d["filtered"] < d["rows"] and d["afterEsc"] == d["rows"]
    assert d["planned"] >= 1 and d["plannedStates"] == ["planned"]
    assert d["groupCollapsed"] == 1 and d["evilRows"] >= 1 and d["pwned"] is None
