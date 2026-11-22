<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: wazuh

## 0.1.0

- The SIEM provider: the manager, the indexer and the dashboard (product 4.14.9, each image pinned by
  digest) as compose_app containers; the `siem-source` and `hot-index` slots (provisional).
- The contract in the README: ports, enrolment, secrets, the alert and archive streams, the syslog input
  and the alert webhook (`homelabnext.alert.created` 1.2).
- A private CA for the stack's internal TLS, create-only; the indexer's accounts hashed by its own tool.
- Native rules loaded with the manager's configuration test and a rollback, an alert integration, a
  retention policy, health that checks live processes, export and restore.
