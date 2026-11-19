# SPDX-License-Identifier: Apache-2.0
"""The publishing module's code (``modules/publishing``; its README says what it is and why).

The lab's only egress path for published content: a gate (TLP, deny-list, secret and posture
patterns) in front of two adapters (a static-site deploy with a pinned deploy tool, and an
object-store podcast feed), run in one of three modes: ``stage`` (the gate and the would-be
publish set, no network at all), ``dry-run`` (read-only requests only) or ``live``.

Standard library only (plus the shared ``tlp``, ``notify`` and ``state`` libraries).
"""
