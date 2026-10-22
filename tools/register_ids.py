#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: register-ids
#   kind: check
#   purpose: Fail when a record vanished, a key occurs twice, or a record carries no uid.
#   owner: maintainers
#   trigger: [make:ids-check, pre-commit:register-ids-check-dupes, pre-commit:register-ids-check-lost, pre-commit:register-ids-check-uids]
#   invariant: [M-16, M-17]
#   inputs: record directories (lessons, runbooks, the strategy records), invariants.yml and git history
#   outputs: one line per lost, duplicate or uid-less record
#   exit:
#     "0": nothing lost, duplicated or without a uid
#     "1": a record vanished, a key occurs twice, or a record has no uid
#     "2": usage error
"""register_ids.py - thin wrapper so hooks can call the id tool without installing the package.

The implementation is ``homelabnext.registers.idcli`` (also reachable as ``hnx ids``).
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from homelabnext.registers.idcli import main

if __name__ == "__main__":
    sys.exit(main())
