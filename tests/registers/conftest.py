# SPDX-License-Identifier: Apache-2.0
import copy
import pathlib

import pytest
import yaml

EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "examples" / "registers"


@pytest.fixture(autouse=True)
def _ids_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMELABNEXT_IDS_STATE", str(tmp_path / "idstate"))
    monkeypatch.delenv("REGISTER_IDS_ALLOW_DROP", raising=False)


@pytest.fixture
def examples():
    return EXAMPLES


@pytest.fixture
def lessons():
    return yaml.safe_load((EXAMPLES / "lessons.yml").read_text())


@pytest.fixture
def clone():
    return copy.deepcopy
