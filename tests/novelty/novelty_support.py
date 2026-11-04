# SPDX-License-Identifier: Apache-2.0
"""Deterministic lake rows for the novelty tests (documentation addresses only, no clock)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

AS_OF = datetime(2026, 3, 10, tzinfo=UTC)
SPEC: dict[str, Any] = {
    "schema_version": "1.0",
    "profiles": [
        {
            "id": "host-dst-port",
            "table": "network_activity",
            "entity": "src_endpoint.ip",
            "values": ["dst_endpoint.port"],
            "learn_days": 4,
            "half_life_days": 2,
            "score_hours": 24,
            "min_support": 2,
            "entity_min_samples": 4,
            "max_values_per_entity": 3,
            "emit_at": 0.25,
            "max_findings": 10,
        }
    ],
}
SITE = {"tlp_readers": [{"reader": "analyzer:novelty", "ceiling": "amber", "why": "tests"}]}


def net(i: int, *, day: int, src: str, port: int, hour: int = 12, tlp: str = "green"):
    return {
        "uid": f"net-{day:02d}-{i:04d}",
        "tlp": tlp,
        "time": datetime(2026, 3, day, hour, tzinfo=UTC) + timedelta(seconds=i),
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "type_uid": 400106,
        "severity_id": 1,
        "src_endpoint": {"ip": src, "port": 50000 + i},
        "dst_endpoint": {"ip": "203.0.113.5", "port": port},
        "protocol_name": "tcp",
        "direction_id": 2,
    }


def rows() -> list[dict[str, Any]]:
    """192.0.2.10 talks to 443 every learning day and to 22 for the first time in the scoring
    window; 192.0.2.11 appears only in the scoring window; a red row of 192.0.2.10 is above
    the analyzer's amber ceiling and must not count."""
    out = []
    i = 0
    for day in (5, 6, 7, 8):
        for _ in range(2):
            out.append(net(i, day=day, src="192.0.2.10", port=443))
            i += 1
    out.append(net(i, day=7, src="192.0.2.10", port=22, tlp="red"))
    out.append(net(i + 1, day=9, src="192.0.2.10", port=22))
    out.append(net(i + 2, day=9, src="192.0.2.11", port=443, tlp="amber"))
    out.append(net(i + 3, day=9, src="192.0.2.10", port=443))
    out.append(net(i + 4, day=10, src="192.0.2.10", port=8080))  # at as_of: outside
    return out
