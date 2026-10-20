# SPDX-License-Identifier: Apache-2.0
import pathlib
import shutil

import pytest
from strategy_helpers import EXAMPLE, REPO


@pytest.fixture(autouse=True)
def _ids_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMELABNEXT_IDS_STATE", str(tmp_path / "idstate"))


@pytest.fixture
def lab(tmp_path) -> pathlib.Path:
    """A copy of the example strategy with its siblings: the review policy, the invariants
    register and the service registry (what the validation resolves bindings against)."""
    root = tmp_path / "lab"
    shutil.copytree(EXAMPLE, root / "strategy")
    shutil.copy(REPO / "examples" / "review-policy.yml", root / "review-policy.yml")
    shutil.copy(REPO / "examples" / "registers" / "invariants.yml", root / "invariants.yml")
    shutil.copy(REPO / "examples" / "services.yml", root / "services.yml")
    return root / "strategy"


@pytest.fixture
def records(tmp_path) -> pathlib.Path:
    from homelabnext.records.decider import init_tree

    init_tree(tmp_path / "records")
    return tmp_path / "records"
