# SPDX-License-Identifier: Apache-2.0
"""The script catalog: headers, the generated catalog, and the checks that keep it true.

* M-01 ``hnx scripts catalog --check``: every script has a valid header; the committed catalog
  (``docs/scripts/catalog.json`` + ``.md``) is what the headers produce now.
* M-02 ``hnx scripts reality``: the headers' triggers are exactly the discovered callers; no
  scheduled or called script is uncatalogued; no active script is uncalled; ids are unique.
* M-04 ``hnx scripts runner-lint``: every ``kind: check`` script runs through an invariants
  criterion and no timer runs one directly.

What counts as a script and the header format: docs/scripts.md.
"""

from .catalog import Catalog, build, check_current, tracked_files
from .header import MARKER, HeaderError, find_header, validate
from .reality import Allow, AllowError, discover, load_allow, reality_problems, runner_problems

__all__ = [
    "MARKER",
    "Allow",
    "AllowError",
    "Catalog",
    "HeaderError",
    "build",
    "check_current",
    "discover",
    "find_header",
    "load_allow",
    "reality_problems",
    "runner_problems",
    "tracked_files",
    "validate",
]
