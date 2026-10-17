# SPDX-License-Identifier: Apache-2.0
"""ATT&CK-id validation tests (P6.5).

Fixtures use SYNTHETIC rule slugs and technique ids - never reference a live-lab rule number or
a specific internal engine. The point is to exercise the mechanism (snapshot loader + validator
+ --suggest-parent + CLI) end to end, not to assert anything about the real detections tree.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext.detections import attack
from homelabnext.detections.cli import main

# ---- a dataclass-like stand-in; the validator duck-types on det_id + attack_techniques ----


class FakeRule:
    def __init__(self, slug: str, techniques: list[str]):
        self.slug = slug
        self.attack_techniques = techniques

    @property
    def det_id(self) -> str:
        return f"det:{self.slug}"


SYNTHETIC_IDS = [
    "T9001",
    "T9001.001",
    "T9001.002",
    "T9002",
    "T9003.004",
]


def _write_yaml_snapshot(p: Path, *, extra: dict | None = None) -> Path:
    doc = {
        "engine": "fake",
        "engine_version": "0.0.0-test",
        "attack_version": "vTEST",
        "snapshot_date": "2026-01-02",
        "technique_ids": list(SYNTHETIC_IDS),
    }
    if extra:
        doc.update(extra)
    import yaml

    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


# ---- parent_of ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tid, parent",
    [
        ("T1059", None),
        ("T1059.001", "T1059"),
        ("T9999.123", "T9999"),
        ("bogus", None),
        ("", None),
    ],
)
def test_parent_of(tid, parent):
    assert attack.parent_of(tid) == parent


# ---- snapshot loader ---------------------------------------------------------------------


def test_load_snapshot_yaml(tmp_path):
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    assert snap.engine == "fake"
    assert snap.engine_version == "0.0.0-test"
    assert snap.attack_version == "vTEST"
    assert snap.snapshot_date == "2026-01-02"
    assert snap.technique_ids == frozenset(SYNTHETIC_IDS)
    assert snap.knows("T9001.001")
    assert not snap.knows("T9001.999")


def test_load_snapshot_json(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(
        json.dumps(
            {
                "engine": "fake",
                "engine_version": "0.0.0-test",
                "attack_version": "vTEST",
                "snapshot_date": "2026-01-02",
                "technique_ids": list(SYNTHETIC_IDS),
            }
        ),
        encoding="utf-8",
    )
    snap = attack.load_snapshot(p)
    assert snap.technique_ids == frozenset(SYNTHETIC_IDS)


def test_load_snapshot_plain_text(tmp_path):
    p = tmp_path / "s.txt"
    p.write_text(
        "# engine: fake\n"
        "# engine_version: 0.0.0-test\n"
        "# attack_version: vTEST\n"
        "# snapshot_date: 2026-01-02\n"
        "\n"
        "T9001\n"
        "T9001.001\n"
        "T9002\n",
        encoding="utf-8",
    )
    snap = attack.load_snapshot(p)
    assert snap.engine == "fake"
    assert snap.technique_ids == frozenset({"T9001", "T9001.001", "T9002"})


def test_load_snapshot_accepts_attack_prefix_and_lowercase(tmp_path):
    p = tmp_path / "s.txt"
    p.write_text(
        "# engine: fake\n"
        "# engine_version: 0\n"
        "# attack_version: 0\n"
        "# snapshot_date: 2026-01-02\n"
        "attack.T1059.001\n"
        "t1086\n",
        encoding="utf-8",
    )
    snap = attack.load_snapshot(p)
    assert snap.technique_ids == frozenset({"T1059.001", "T1086"})


@pytest.mark.parametrize(
    "mutator, msg",
    [
        (lambda d: d.pop("engine"), "engine"),
        (lambda d: d.pop("engine_version"), "engine_version"),
        (lambda d: d.pop("snapshot_date"), "snapshot_date"),
        (lambda d: d.pop("attack_version"), "attack_version"),
        (lambda d: d.update({"technique_ids": []}), "no technique ids"),
        (lambda d: d.update({"technique_ids": ["not-an-id"]}), "technique id"),
        (lambda d: d.update({"technique_ids": "nope"}), "technique_ids"),
    ],
)
def test_load_snapshot_rejects_bad_shape(tmp_path, mutator, msg):
    import yaml

    doc = {
        "engine": "fake",
        "engine_version": "0.0.0-test",
        "attack_version": "vTEST",
        "snapshot_date": "2026-01-02",
        "technique_ids": list(SYNTHETIC_IDS),
    }
    mutator(doc)
    p = tmp_path / "s.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(attack.SnapshotError, match=msg):
        attack.load_snapshot(p)


# ---- validate_rules ----------------------------------------------------------------------


def test_validate_rules_all_known_is_empty(tmp_path):
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    rules = [
        FakeRule("alpha", ["T9001.001"]),
        FakeRule("beta", ["T9002"]),
    ]
    assert attack.validate_rules(rules, snap) == []


def test_validate_rules_unknown_bare_technique(tmp_path):
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    probs = attack.validate_rules([FakeRule("gamma", ["T9999"])], snap)
    assert len(probs) == 1
    assert "det:gamma" in probs[0] and "T9999" in probs[0] and "not in" in probs[0]


def test_validate_rules_unknown_subtechnique_without_suggest(tmp_path):
    # ``T9001`` IS known; ``T9001.999`` is a sub-technique that is NOT in the snapshot.
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    probs = attack.validate_rules([FakeRule("delta", ["T9001.999"])], snap)
    assert len(probs) == 1
    assert "T9001.999" in probs[0]
    # without --suggest-parent, no 'tag the parent' guidance appears
    assert "tag the parent" not in probs[0]


def test_validate_rules_suggests_parent_when_known(tmp_path):
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    probs = attack.validate_rules([FakeRule("delta", ["T9001.999"])], snap, suggest_parent=True)
    assert len(probs) == 1
    assert "T9001.999" in probs[0]
    assert "parent T9001 IS known" in probs[0]
    assert "tag the parent" in probs[0]


def test_validate_rules_suggests_nothing_when_parent_also_unknown(tmp_path):
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    # ``T8888`` is not in the snapshot and neither is its (synthetic) sub.
    probs = attack.validate_rules([FakeRule("eps", ["T8888.001"])], snap, suggest_parent=True)
    assert len(probs) == 1
    assert "T8888.001" in probs[0]
    assert "tag the parent" not in probs[0]


def test_validate_rules_order_is_stable(tmp_path):
    snap = attack.load_snapshot(_write_yaml_snapshot(tmp_path / "s.yml"))
    rules = [
        FakeRule("one", ["T8888", "T7777"]),  # both unknown
        FakeRule("two", ["T9001.001"]),  # known
        FakeRule("three", ["T6666"]),
    ]
    probs = attack.validate_rules(rules, snap)
    # 2 unknowns in rule 'one', zero in 'two', 1 in 'three' - total 3, in rule order, id order.
    assert len(probs) == 3
    assert "det:one" in probs[0] and "T8888" in probs[0]
    assert "det:one" in probs[1] and "T7777" in probs[1]
    assert "det:three" in probs[2] and "T6666" in probs[2]


def test_validate_rules_accepts_bare_iterable_of_ids(tmp_path):
    # Callers that already hold a backend's advertised set do not have to construct a snapshot.
    probs = attack.validate_rules([FakeRule("f", ["T9999"])], {"T9001", "T9002"})
    assert len(probs) == 1 and "T9999" in probs[0]


# ---- CLI ---------------------------------------------------------------------------------


def _mini_detections_tree(root: Path, *, techniques: list[str]) -> Path:
    """A valid, minimal detections tree with ONE synthetic rule."""
    rule_file = root / "sigma" / "execution" / "ping.yml"
    rule_file.parent.mkdir(parents=True, exist_ok=True)
    rule_file.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "title: Ping canary\n"
        "det: det:ping\n"
        "description: synthetic ATT&CK validation canary\n"
        "status: experimental\n"
        "logsource: {category: process_creation}\n"
        "detection:\n"
        "  sel:\n"
        "    Image|endswith: '\\ping.exe'\n"
        "  condition: sel\n"
        "level: low\n"
        "tags: ["
        + ", ".join(["attack.execution"] + [f"attack.{t.lower()}" for t in techniques])
        + "]\n",
        encoding="utf-8",
    )
    return rule_file


def test_cli_validate_techniques_pass(tmp_path):
    _mini_detections_tree(tmp_path, techniques=["T9001.001"])
    snap = _write_yaml_snapshot(tmp_path / "snap.yml")
    rc = main(
        [
            "--root",
            str(tmp_path),
            "validate-techniques",
            "--snapshot",
            str(snap),
        ]
    )
    assert rc == 0


def test_cli_validate_techniques_fail_without_suggest(tmp_path, capsys):
    _mini_detections_tree(tmp_path, techniques=["T9001.999"])
    snap = _write_yaml_snapshot(tmp_path / "snap.yml")
    rc = main(["--root", str(tmp_path), "validate-techniques", "--snapshot", str(snap)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "T9001.999" in out and "tag the parent" not in out


def test_cli_validate_techniques_suggest_parent(tmp_path, capsys):
    _mini_detections_tree(tmp_path, techniques=["T9001.999"])
    snap = _write_yaml_snapshot(tmp_path / "snap.yml")
    rc = main(
        [
            "--root",
            str(tmp_path),
            "validate-techniques",
            "--snapshot",
            str(snap),
            "--suggest-parent",
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "T9001.999" in out
    assert "parent T9001 IS known" in out


def test_cli_falls_back_to_backend_snapshot(tmp_path, monkeypatch):
    # Build a detections tree AND a backend whose default snapshot path points at a snapshot
    # relative to the detections root.
    _mini_detections_tree(tmp_path, techniques=["T9001.001"])
    snap_dir = tmp_path / "attack_snapshots"
    snap_dir.mkdir()
    _write_yaml_snapshot(snap_dir / "wazuh.yml")
    # Without --snapshot, the CLI resolves the backend's default; wazuh's default is
    # ``attack_snapshots/wazuh.yml``.
    rc = main(["--root", str(tmp_path), "validate-techniques", "--backend", "wazuh"])
    assert rc == 0


def test_cli_reports_could_not_measure_when_no_snapshot(tmp_path, capsys):
    _mini_detections_tree(tmp_path, techniques=["T9001.001"])
    # Backend is a brand-new instance with the snapshot cleared, pointed at a non-existent
    # tree. ``_resolve_known_ids`` calls the module-registered backend, so we point the
    # root at an empty tree where the default relative snapshot path misses.
    rc = main(
        [
            "--root",
            str(tmp_path),  # no attack_snapshots/wazuh.yml here
            "validate-techniques",
            "--backend",
            "wazuh",
        ]
    )
    assert rc == 100
    err = capsys.readouterr().err
    assert "no ATT&CK known-id snapshot" in err


# ---- Wazuh backend's known_technique_ids -------------------------------------------------


def test_wazuh_backend_loads_its_snapshot_relative_to_root(tmp_path):
    from homelabnext.detections.backends.wazuh import WazuhStubBackend

    snap_dir = tmp_path / "attack_snapshots"
    snap_dir.mkdir()
    _write_yaml_snapshot(snap_dir / "wazuh.yml")
    be = WazuhStubBackend()
    ids = be.known_technique_ids(tmp_path)
    assert ids == frozenset(SYNTHETIC_IDS)
    # cached by resolved path, so a second call returns the same frozenset instance
    assert be.known_technique_ids(tmp_path) is ids


def test_wazuh_backend_cache_is_per_root(tmp_path):
    # Two different roots must not share a cached result - a stale cache from a previous
    # ``known_technique_ids`` call would otherwise mask that the second root has no snapshot.
    from homelabnext.detections.backends.wazuh import WazuhStubBackend

    first = tmp_path / "a"
    (first / "attack_snapshots").mkdir(parents=True)
    _write_yaml_snapshot(first / "attack_snapshots" / "wazuh.yml")
    second = tmp_path / "b"
    second.mkdir()
    be = WazuhStubBackend()
    assert be.known_technique_ids(first) == frozenset(SYNTHETIC_IDS)
    assert be.known_technique_ids(second) == frozenset()


def test_wazuh_backend_returns_empty_without_snapshot(tmp_path):
    from homelabnext.detections.backends.wazuh import WazuhStubBackend

    be = WazuhStubBackend()
    assert be.known_technique_ids(tmp_path) == frozenset()


def test_wazuh_backend_explicit_snapshot_overrides_default(tmp_path):
    from homelabnext.detections.backends.wazuh import WazuhStubBackend

    custom = tmp_path / "elsewhere.yml"
    _write_yaml_snapshot(custom)
    be = WazuhStubBackend(known_ids_snapshot=custom)
    assert be.known_technique_ids() == frozenset(SYNTHETIC_IDS)


# ---- Repo-level sanity: the shipped example rules match the shipped snapshot -------------


def test_shipped_example_rules_validate_against_shipped_wazuh_snapshot():
    repo = Path(__file__).resolve().parents[2]
    snap_path = repo / "detections" / "attack_snapshots" / "wazuh.yml"
    if not snap_path.exists():  # not shipped yet (another worker's slice)
        pytest.skip("no shipped wazuh snapshot in this repo")
    from homelabnext.detections.sigma import load_rules

    snap = attack.load_snapshot(snap_path)
    assert attack.validate_rules(load_rules(repo / "detections"), snap) == []
