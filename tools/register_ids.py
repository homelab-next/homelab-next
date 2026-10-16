#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""register_ids.py - thin wrapper so hooks can call the id tool without installing the package.

The implementation is ``homelabnext.registers.idcli`` (also reachable as ``hnx ids``).
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from homelabnext.registers.idcli import main

if __name__ == "__main__":
    sys.exit(main())
