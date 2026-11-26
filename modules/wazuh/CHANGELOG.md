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
- `wazuh_json_decoder_excluded` (default false): the manager skips the product's generic JSON decoder file so a site's own decoders for JSON lines (Zeek) get first refusal; the site ships replacements for `json` and `json-msgraph` as native decoders.
- `wazuh_json_decoder_excluded` is applied only after the site's replacement `json` decoder is installed: a first install no longer starts the manager with the stock decoder excluded and no replacement (it refused its rules and never became healthy). The role renders the exclusion after the native decoders load, restarts the manager once, and refuses a site that asks for it with no `json` decoder.

- The manager's pid directory is a tmpfs, so a hard reset can no longer leave stale pid files that make the product's start skip every daemon; the alert stream's freshness is part of health; a liveness timer writes `siem_*` textfile metrics (`wazuh_textfile_dir`, `wazuh_alerts_max_age_seconds`).
