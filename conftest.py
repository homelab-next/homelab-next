# SPDX-License-Identifier: Apache-2.0
"""Suite-wide test plugins.  ``tests/network_guard.py``: no network beyond loopback unless a test
is marked ``live`` (checklist Q-03, Q-11).  ``tests/suite_policy.py``: per-suite time budgets, no
silent skips, quarantine with owner and expiry (checklist Q-02)."""

pytest_plugins = ["tests.network_guard", "tests.suite_policy"]
