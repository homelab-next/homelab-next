# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os

import pytest
import yaml
from cust_helpers import make_doc, write_custom

from homelabnext.customization import load_tree, resolve_settings
from homelabnext.customization.loader import ENV_CONFIG, ENV_DIR, load_all


def test_loads_yaml_json_and_suffixed_names(tmp_path):
    write_custom(tmp_path, "a", make_doc(id="custom:a-one"))
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "thing.customization.yml").write_text(
        yaml.safe_dump(make_doc(id="custom:b-two"))
    )
    (tmp_path / "b" / "notes.yml").write_text("not: a customization")
    items, problems = load_tree(tmp_path, "local")
    assert [c.id for c in items] == ["custom:a-one", "custom:b-two"]
    assert problems == []
    assert all(c.origin == "local" and not c.schema_errors for c in items)


def test_yaml_dates_stay_strings(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "customization.yml").write_text(
        yaml.safe_dump(make_doc()).replace("'2026-12-01'", "2026-12-01")
    )
    (c,) = load_tree(tmp_path, "local")[0]
    assert c.doc["review_by"] == "2026-12-01" and c.schema_errors == []


def test_duplicate_yaml_key_is_a_load_problem(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "customization.yml").write_text("id: custom:a\nid: custom:b\n")
    items, problems = load_tree(tmp_path, "local")
    assert items == [] and problems[0].code == "CU012" and "duplicate key" in problems[0].message


def test_unparseable_is_a_load_problem(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "customization.json").write_text("{not json")
    assert load_tree(tmp_path, "local")[1][0].code == "CU012"


def test_symlinked_customization_is_ignored(tmp_path):
    real = tmp_path / "elsewhere"
    write_custom(real, "a", make_doc())
    link_dir = tmp_path / "overlay"
    link_dir.mkdir()
    os.symlink(real / "a" / "customization.json", link_dir / "customization.json")
    assert load_tree(link_dir, "local") == ([], [])


def test_env_var_and_config_discovery(tmp_path):
    cfg = tmp_path / "cfg.yml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "customizations_dir": [str(tmp_path / "from-config")],
                "enable": [{"id": "custom:x-one", "hosts": ["host-a"]}],
            }
        )
    )
    s = resolve_settings(
        dirs=[str(tmp_path / "flag")],
        enable=["custom:x-two=host-b,host-c", "custom:x-three"],
        env={
            ENV_DIR: os.pathsep.join([str(tmp_path / "env1"), str(tmp_path / "flag")]),
            ENV_CONFIG: str(cfg),
        },
    )
    assert [p.name for p in s.local_dirs] == ["from-config", "flag", "env1"]  # de-duplicated
    assert s.enabled == {
        "custom:x-one": ["host-a"],
        "custom:x-two": ["host-b", "host-c"],
        "custom:x-three": [],
    }


def test_public_and_local_are_both_loaded_with_origin(tmp_path):
    pub, loc = tmp_path / "pub", tmp_path / "loc"
    write_custom(pub, "p", make_doc(id="custom:pub-one"))
    write_custom(loc, "l", make_doc(id="custom:loc-one"))
    s = resolve_settings(dirs=[str(loc)], env={}, public_dir=pub)
    items, _ = load_all(s)
    assert {(c.id, c.origin) for c in items} == {
        ("custom:pub-one", "public"),
        ("custom:loc-one", "local"),
    }


@pytest.mark.parametrize("missing", ["reason", "owner", "review_by"])
def test_missing_mandatory_field_is_a_schema_error(tmp_path, missing):
    write_custom(tmp_path, "a", make_doc(**{missing: None}))
    (c,) = load_tree(tmp_path, "local")[0]
    assert any(missing in e for e in c.schema_errors)
