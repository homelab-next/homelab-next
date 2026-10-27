# SPDX-License-Identifier: Apache-2.0
"""The core's own notify pairs: every problem title the core registers with
:meth:`homelabnext.notify.core.Notifier.register_pair`, and its recovery title.

This is the one place they are written.  The components that page (the broker, the status hub,
the power monitor, the model-call budget, the serving-config check) take their titles from here,
so the list is what they register, not a copy of it; ``tests/notify/test_core_pairs.py`` runs
each registration and fails on a title missing here.  The module loader reads it
(:class:`homelabnext.modules.loader.CoreNames`) so that no module declares one of these titles:
the notifier keys its pairs by problem title, so a module that took one would change the
recovery the core's own alert clears with.
"""

from __future__ import annotations

from types import MappingProxyType

BROKER_APPROVAL = ("Broker approval needed", "Broker approval settled")
BROKER_LANE_QUOTA = ("Broker lane quota reached", "Broker lane quota cleared")
MODEL_CALL_BUDGET = ("Model call budget exceeded", "Model call budget back within limits")
SERVING_MISMATCH = ("Model serving config mismatch", "Model serving config matches")
SERVING_UNREACHABLE = ("Model backend unreachable", "Model backend reachable")
SERVING_ERROR = ("Model probe failed", "Model probe recovered")
STATUS_ITEM = ("Status item needs attention", "Status item recovered")
UPS_ON_BATTERY = ("UPS on battery", "UPS back on line power")

#: problem title -> recovery title, for every pair above
CORE_PAIRS = MappingProxyType(
    dict(
        (
            BROKER_APPROVAL,
            BROKER_LANE_QUOTA,
            MODEL_CALL_BUDGET,
            SERVING_MISMATCH,
            SERVING_UNREACHABLE,
            SERVING_ERROR,
            STATUS_ITEM,
            UPS_ON_BATTERY,
        )
    )
)

__all__ = [
    "BROKER_APPROVAL",
    "BROKER_LANE_QUOTA",
    "CORE_PAIRS",
    "MODEL_CALL_BUDGET",
    "SERVING_ERROR",
    "SERVING_MISMATCH",
    "SERVING_UNREACHABLE",
    "STATUS_ITEM",
    "UPS_ON_BATTERY",
]
