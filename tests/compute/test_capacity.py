# SPDX-License-Identifier: Apache-2.0
"""Node capacity: ``_nodes.yml`` ``capacity`` and ``pools`` against the guests placed on each node
(:func:`homelabnext.compute.validate.validate`).  A node that declares neither asks nothing."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.cli import main as hnx
from homelabnext.compute import load_nodes
from homelabnext.compute.model import ComputeError

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "examples" / "lab-topology"


def _lab(tmp_path: Path) -> tuple[Path, list[str]]:
    lab = tmp_path / "lab"
    shutil.copytree(LAB, lab)
    return lab, ["guests", "validate", str(lab / "guests"), "--site", str(lab / "site.yml")]


def _edit(path: Path, fn) -> None:
    doc = yaml.safe_load(path.read_text())
    fn(doc)
    path.write_text(yaml.safe_dump(doc))


def test_the_example_lab_fits_and_validate_prints_each_node_s_use(tmp_path, capsys):
    _, args = _lab(tmp_path)
    assert hnx(args) == 0
    out = capsys.readouterr().out
    assert "hv-1: 5 guests, cores 20/28, memory 38/56 GiB, fast 352/900 GB" in out
    assert "hv-2: 8 guests, cores 21/28" in out


@pytest.mark.parametrize(
    ("node_edit", "message"),
    [
        (
            lambda n: n["capacity"].update(cpu_overcommit=1),
            "guests ask for 20 cores, more than its 14",
        ),
        (lambda n: n["capacity"]["reserve"].update(memory_mb=40000), "more than the 25536 MB"),
        (
            lambda n: n["pools"]["fast"].update(size_gb=300),
            "352 GB on pool 'fast', more than its 300",
        ),
        (
            lambda n: n.update(pools={"bulk": {"size_gb": 9000, "media": "hdd"}}),
            "which it does not have",
        ),
    ],
)
def test_a_node_its_guests_do_not_fit_is_refused(tmp_path, capsys, node_edit, message):
    lab, args = _lab(tmp_path)
    _edit(lab / "guests" / "_nodes.yml", lambda d: node_edit(d["nodes"]["hv-1"]))
    assert hnx(args) == 1
    err = capsys.readouterr().err
    assert "_nodes.yml hv-1" in err and message in err, err


def test_a_retired_guest_frees_its_share_and_a_planned_one_takes_it(tmp_path, capsys):
    lab, args = _lab(tmp_path)
    _edit(
        lab / "guests" / "_nodes.yml",
        lambda d: d["nodes"]["hv-1"]["pools"]["fast"].update(size_gb=352),
    )
    assert hnx(args) == 0  # exactly full
    guest = next(f for f in (lab / "guests").glob("[!_]*.yml")
                 if (yaml.safe_load(f.read_text()).get("placement") or {}).get("node") == "hv-1"
                 and yaml.safe_load(f.read_text()).get("resources"))  # fmt: skip
    _edit(guest, lambda d: d.update(status="planned"))
    assert hnx(args) == 0  # planned still counts: same total
    _edit(guest, lambda d: d.update(status="retired"))
    capsys.readouterr()
    assert hnx(args) == 0
    assert "hv-1: 4 guests" in capsys.readouterr().out


def test_a_node_without_capacity_or_pools_asks_nothing(tmp_path, capsys):
    lab, args = _lab(tmp_path)
    _edit(
        lab / "guests" / "_nodes.yml",
        lambda d: [n.pop(k) for n in d["nodes"].values() for k in ("capacity", "pools")],
    )
    assert hnx(args) == 0
    assert "cores" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("spec", "words"),
    [
        ({"capacity": {"threads": 0, "memory_mb": 1}}, "positive whole numbers"),
        ({"capacity": {"threads": 4, "memory_mb": 1024, "gpus": 1}}, "takes threads"),
        (
            {"capacity": {"threads": 4, "memory_mb": 1024, "reserve": {"threads": 4}}},
            "leaves no threads",
        ),
        ({"capacity": {"threads": 4, "memory_mb": 1024, "cpu_overcommit": 0.5}}, "from 1 to 16"),
        ({"capacity": {"threads": 4, "memory_mb": 1024, "cpu_overcommit": True}}, "from 1 to 16"),
        ({"pools": {}}, "a mapping of pool name"),
        ({"pools": {"fast": {"size_gb": "big"}}}, "positive whole number"),
        ({"pools": {"fast": {"size_gb": 10, "media": "tape"}}}, "nvme, ssd or hdd"),
        ({"pools": {"fast": {"size_gb": 10, "raid": "z2"}}}, "takes size_gb and media"),
        ({"capacity": {"threads": 4, "memory_mb": 1024, "reserve": None}}, "reserve"),
        ({"pools": {"Bad Name": {"size_gb": 10}}}, "not one a disk can name"),
        ({"pools": {1: {"size_gb": 10}}}, "not one a disk can name"),
    ],
)
def test_a_malformed_node_spec_is_refused(tmp_path, spec, words):
    p = tmp_path / "_nodes.yml"
    p.write_text(yaml.safe_dump({"nodes": {"hv": spec}}))
    with pytest.raises(ComputeError, match=words):
        load_nodes(p)


def test_a_guest_on_a_node_the_file_does_not_list_is_not_checked_against_nothing(tmp_path, capsys):
    lab, args = _lab(tmp_path)
    guest = next(f for f in (lab / "guests").glob("[!_]*.yml")
                 if (yaml.safe_load(f.read_text()).get("placement") or {}).get("node") == "hv-1"
                 and yaml.safe_load(f.read_text()).get("resources"))  # fmt: skip
    _edit(guest, lambda d: d["placement"].update(node="hv1"))  # a typo
    assert hnx(args) == 1
    assert (
        "1 guest(s) are placed on 'hv1', which _nodes.yml does not list" in capsys.readouterr().err
    )


def test_the_vcpu_budget_is_exact_for_a_fractional_ratio(tmp_path):
    p = tmp_path / "_nodes.yml"
    p.write_text(
        yaml.safe_dump(
            {
                "nodes": {
                    "hv": {"capacity": {"threads": 100, "memory_mb": 1024, "cpu_overcommit": 1.15}}
                }
            }
        )
    )
    assert load_nodes(p)["hv"]["capacity"]["for_guests"]["vcpus"] == 115  # not int(114.99999)
