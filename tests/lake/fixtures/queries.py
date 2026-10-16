# SPDX-License-Identifier: Apache-2.0
"""The 30 portable queries used for engine parity (DuckDB vs FakeLake vs the recorded cassette).

Portable subset: ``SELECT`` with joins, ``WHERE``, ``GROUP BY``/``HAVING``, ``ORDER BY``,
``LIMIT``, CTEs, ``CASE``, ``COALESCE``, ``ROUND``, ``LIKE``, ``IN``, aggregates, named ``:param``s,
timestamps compared with ``'YYYY-MM-DD HH:MM:SS'`` literals (UTC). Not portable, so not used:
struct field access (``dst_endpoint.port``), engine functions (``date_trunc``, ``list_*``).
"""

from __future__ import annotations

T = "2026-03-01 "
QUERIES: list[dict] = [
    {"name": "q01-count-auth", "sql": "SELECT count(*) AS n FROM authentication"},
    {
        "name": "q02-users",
        "sql": "SELECT user_name, count(*) AS n FROM authentication GROUP BY user_name ORDER BY user_name",
    },
    {"name": "q03-failures", "sql": "SELECT count(*) AS n FROM authentication WHERE status_id = 2"},
    {
        "name": "q04-param-user",
        "sql": "SELECT uid FROM authentication WHERE user_name = :u ORDER BY uid LIMIT 5",
        "params": {"u": "alice"},
    },
    {
        "name": "q05-window",
        "sql": f"SELECT uid FROM authentication WHERE time >= '{T}02:00:00' AND time < '{T}03:00:00' ORDER BY uid",
    },
    {
        "name": "q06-param-time",
        "sql": "SELECT count(*) AS n FROM authentication WHERE time >= :t0",
        "params": {"t0": "2026-03-01 04:00:00"},
    },
    {
        "name": "q07-min-max-time",
        "sql": "SELECT min(time) AS first_seen, max(time) AS last_seen FROM authentication",
    },
    {
        "name": "q08-by-activity",
        "sql": "SELECT activity_id, count(*) AS n FROM authentication GROUP BY activity_id ORDER BY activity_id",
    },
    {
        "name": "q09-mfa-bool",
        "sql": "SELECT is_mfa, count(*) AS n FROM authentication GROUP BY is_mfa ORDER BY is_mfa",
    },
    {
        "name": "q10-having",
        "sql": "SELECT user_name, count(*) AS n FROM authentication WHERE status_id = 2 GROUP BY user_name HAVING count(*) >= 3 ORDER BY n DESC, user_name",
    },
    {
        "name": "q11-protocols",
        "sql": "SELECT DISTINCT auth_protocol FROM authentication ORDER BY auth_protocol",
    },
    {
        "name": "q12-like",
        "sql": "SELECT count(*) AS n FROM authentication WHERE message LIKE 'login f%'",
    },
    {
        "name": "q13-in",
        "sql": "SELECT count(*) AS n FROM authentication WHERE user_name IN ('alice', 'bob')",
    },
    {
        "name": "q14-net-sums",
        "sql": "SELECT protocol_name, sum(bytes_in) AS bi, sum(bytes_out) AS bo FROM network_activity GROUP BY protocol_name ORDER BY protocol_name",
    },
    {
        "name": "q15-net-top",
        "sql": "SELECT uid, bytes_in FROM network_activity ORDER BY bytes_in DESC, uid LIMIT 5",
    },
    {
        "name": "q16-net-null-conn",
        "sql": "SELECT count(*) AS n FROM network_activity WHERE connection_uid IS NULL",
    },
    {
        "name": "q17-net-avg",
        "sql": "SELECT round(avg(bytes_in), 2) AS avg_in FROM network_activity",
    },
    {
        "name": "q18-dns-top",
        "sql": "SELECT query_hostname, count(*) AS n FROM dns_activity GROUP BY query_hostname ORDER BY n DESC, query_hostname LIMIT 3",
    },
    {"name": "q19-dns-nx", "sql": "SELECT count(*) AS n FROM dns_activity WHERE rcode_id <> 0"},
    {
        "name": "q20-dns-types",
        "sql": "SELECT query_type, count(*) AS n FROM dns_activity GROUP BY query_type ORDER BY query_type",
    },
    {
        "name": "q21-det-by-id",
        "sql": "SELECT detection_id, count(*) AS n FROM detection_finding GROUP BY detection_id ORDER BY detection_id",
    },
    {"name": "q22-det-max-risk", "sql": "SELECT max(risk_score) AS top FROM detection_finding"},
    {
        "name": "q23-det-host-avg",
        "sql": "SELECT host_name, round(avg(risk_score), 1) AS avg_risk FROM detection_finding GROUP BY host_name ORDER BY host_name",
    },
    {
        "name": "q24-det-list-col",
        "sql": "SELECT uid, attack_techniques FROM detection_finding ORDER BY uid LIMIT 4",
    },
    {
        "name": "q25-vuln-high",
        "sql": "SELECT count(*) AS n FROM vulnerability_finding WHERE cvss_score >= 7.0",
    },
    {
        "name": "q26-vuln-fixable",
        "sql": "SELECT fix_available, count(*) AS n FROM vulnerability_finding GROUP BY fix_available ORDER BY fix_available",
    },
    {
        "name": "q27-vuln-distinct-cve",
        "sql": "SELECT count(DISTINCT cve_uid) AS n FROM vulnerability_finding",
    },
    {
        "name": "q28-vuln-pkg-avg",
        "sql": "SELECT package_name, round(avg(cvss_score), 2) AS avg_cvss FROM vulnerability_finding GROUP BY package_name ORDER BY package_name",
    },
    {
        "name": "q29-join-host",
        "sql": "SELECT d.host_name, count(*) AS pairs FROM detection_finding d JOIN vulnerability_finding v ON d.host_name = v.host_name GROUP BY d.host_name ORDER BY d.host_name",
    },
    {
        "name": "q30-case-cte",
        "sql": "WITH b AS (SELECT CASE WHEN severity_id >= 3 THEN 'high' ELSE 'low' END AS band, coalesce(message, 'none') AS msg FROM authentication) SELECT band, count(*) AS n FROM b GROUP BY band ORDER BY band",
    },
]
