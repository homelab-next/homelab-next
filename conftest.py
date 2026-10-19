# SPDX-License-Identifier: Apache-2.0
"""Suite-wide test plugins.  ``tests/network_guard.py``: no network beyond loopback unless a test
is marked ``live`` (checklist Q-03, Q-11)."""

pytest_plugins = ["tests.network_guard"]
