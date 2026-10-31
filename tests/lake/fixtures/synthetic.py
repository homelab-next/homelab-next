# SPDX-License-Identifier: Apache-2.0
"""Deterministic synthetic OCSF rows (no randomness, no clock, documentation addresses only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

BASE = datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC)
META = {"version": "1.3.0", "product": "example-sensor", "log_source": "sensor-a"}
#: every TLP label, so each table stores all five (ADR-0033 decision 5)
TLPS = ("clear", "green", "amber", "amber+strict", "red")
USERS = ["alice", "bob", "carol", "dave", "erin"]
HOSTS = [f"srv-{i:02d}.example.internal" for i in range(1, 5)]


def _t(minutes: int) -> datetime:
    return BASE + timedelta(minutes=minutes)


def authentication(n: int = 60) -> list[dict[str, Any]]:
    rows = []
    for i in range(n):
        failed = i % 4 == 3
        rows.append(
            {
                "uid": f"auth-{i:06d}",
                "tlp": TLPS[i % len(TLPS)],
                "time": _t(7 * i),
                "class_uid": 3002,
                "category_uid": 3,
                "activity_id": 2 if i % 3 == 2 else 1,
                "type_uid": 300201,
                "severity_id": 3 if failed else 1,
                "status_id": 2 if failed else 1,
                "message": "login failed" if failed else "login ok",
                "metadata": dict(META),
                "user_name": USERS[i % 5],
                "src_endpoint": {
                    "ip": f"198.51.100.{10 + i % 7}",
                    "port": 40000 + i,
                    "hostname": None,
                },
                "dst_endpoint": {"ip": "192.0.2.20", "port": 22, "hostname": None},
                "logon_type_id": (2, 3, 10)[i % 3],
                "auth_protocol": ("ssh", "rdp", "kerberos")[i % 3],
                "is_mfa": i % 2 == 0,
            }
        )
    return rows


def network_activity(n: int = 40) -> list[dict[str, Any]]:
    rows = []
    for i in range(n):
        rows.append(
            {
                "uid": f"net-{i:06d}",
                "tlp": TLPS[i % len(TLPS)],
                "time": _t(11 * i + 1),
                "class_uid": 4001,
                "category_uid": 4,
                "activity_id": 6,
                "type_uid": 400106,
                "severity_id": 1,
                "src_endpoint": {"ip": f"192.0.2.{10 + i % 5}", "port": 50000 + i},
                "dst_endpoint": {"ip": f"203.0.113.{i % 9}", "port": (443, 53, 22, 8080)[i % 4]},
                "protocol_name": "tcp" if i % 3 else "udp",
                "connection_uid": None if i % 5 == 0 else f"conn-{i}",
                "direction_id": 1 + i % 3,
                "bytes_in": 100 * (i + 1) % 977,
                "bytes_out": 37 * (i + 1) % 541,
            }
        )
    return rows


def dns_activity(n: int = 30) -> list[dict[str, Any]]:
    names = ["www.example.com", "mail.example.org", "api.example.net", "cdn.example.com"]
    return [
        {
            "uid": f"dns-{i:06d}",
            "tlp": TLPS[i % len(TLPS)],
            "time": _t(13 * i + 2),
            "class_uid": 4003,
            "category_uid": 4,
            "activity_id": 1,
            "severity_id": 1,
            "src_endpoint": {"ip": f"192.0.2.{10 + i % 5}"},
            "query_hostname": names[i % 4],
            "query_type": ("A", "AAAA", "TXT")[i % 3],
            "rcode_id": 0 if i % 6 else 3,
            "answers": [] if i % 6 == 0 else [f"198.51.100.{i % 50}"],
        }
        for i in range(n)
    ]


def detection_finding(n: int = 12) -> list[dict[str, Any]]:
    dets = ["det:auth-failure-burst", "det:rare-dns-type", "det:large-egress"]
    return [
        {
            "uid": f"det-{i:06d}",
            "tlp": TLPS[i % len(TLPS)],
            "time": _t(37 * i + 3),
            "class_uid": 2004,
            "category_uid": 2,
            "activity_id": 1,
            "severity_id": 2 + i % 3,
            "finding_uid": f"f-{i}",
            "finding_title": f"finding {i}",
            "detection_id": dets[i % 3],
            "risk_score": 10 + 7 * i % 90,
            "confidence_id": 1 + i % 3,
            "attack_techniques": [["T1110"], ["T1071", "T1071.004"], ["T1041"]][i % 3],
            "host_name": HOSTS[i % 4],
        }
        for i in range(n)
    ]


def vulnerability_finding(n: int = 12) -> list[dict[str, Any]]:
    pkgs = ["examplelib", "demo-server", "sample-agent"]
    return [
        {
            "uid": f"vuln-{i:06d}",
            "tlp": TLPS[i % len(TLPS)],
            "time": _t(41 * i + 4),
            "class_uid": 2002,
            "category_uid": 2,
            "activity_id": 1,
            "severity_id": 1 + i % 5,
            "finding_uid": f"v-{i}",
            "cve_uid": f"CVE-2099-{1000 + i % 8}",
            "cvss_score": round(2.0 + (i * 7 % 80) / 10, 1),
            "package_name": pkgs[i % 3],
            "package_version": f"1.{i % 4}.0",
            "fix_available": i % 3 != 0,
            "host_name": HOSTS[i % 4],
        }
        for i in range(n)
    ]


def all_tables() -> dict[str, list[dict[str, Any]]]:
    return {
        "authentication": authentication(),
        "network_activity": network_activity(),
        "dns_activity": dns_activity(),
        "detection_finding": detection_finding(),
        "vulnerability_finding": vulnerability_finding(),
    }
