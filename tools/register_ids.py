#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: register-ids
#   kind: check
#   purpose: Allocate XX-NEW register ids, and fail when an id vanished or occurs twice.
#   owner: maintainers
#   trigger: [make:ids-check, make:ids-resolve, pre-commit:register-ids-check-dupes, pre-commit:register-ids-check-lost, pre-commit:register-ids-resolve]
#   invariant: [M-17]
#   inputs: register files (lessons, runbooks, invariants, queue) and git history
#   outputs: rewritten registers (resolve) or one line per lost or duplicate id
#   exit:
#     "0": nothing lost or duplicated
#     "1": an id vanished or occurs twice
#     "2": usage error
#     "3": resolve rewrote a placeholder
"""register_ids.py - thin wrapper so hooks can call the id tool without installing the package.

The implementation is ``homelabnext.registers.idcli`` (also reachable as ``hnx ids``).
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from homelabnext.registers.idcli import main

if __name__ == "__main__":
    sys.exit(main())
