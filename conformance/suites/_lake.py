# SPDX-License-Identifier: Apache-2.0
"""Synthetic OCSF rows for the lake suites (documentation-range addresses only)."""

from __future__ import annotations

from typing import Any

from ._util import ip

TABLE = "authentication"


def auth_row(uid: str, *, user: str = "alice", time: str = "2026-03-01T08:15:00Z", **over: Any):
    row: dict[str, Any] = {
        "uid": uid,
        "time": time,
        "class_uid": 3002,
        "category_uid": 3,
        "activity_id": 1,
        "type_uid": 300201,
        "severity_id": 1,
        "status_id": 1,
        "metadata": {"version": "1.3.0", "product": "example-sensor", "log_source": "sensor-a"},
        "user_name": user,
        "src_endpoint": {
            "ip": ip(10, 1),
            "port": 52114,
            "hostname": "ws-01.example.internal",
        },
        "dst_endpoint": {"ip": ip(20), "port": 22},
        "logon_type_id": 3,
        "auth_protocol": "ssh",
        "is_mfa": False,
        "message": "login ok",
    }
    row.update(over)
    return row
