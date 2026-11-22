<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: module `dfir-iris`

## 0.1.0 (unreleased)

- First version: the `case-management` provider (a new provisional slot) on DFIR-IRIS 2.4.29: the
  web app and its worker (one image, two containers), the product's PostgreSQL 12 image, RabbitMQ and
  the product's TLS front, all pinned by tag and digest, as `compose_app` containers in the module's
  slice, none as root. HTTPS only on the guest's own address with a certificate from the lab CA; the
  database, the broker, the app and the worker publish no port.
- Credentials by `secret:` name (`dfir-iris/db-password`, `db-admin-password`, `session-key`,
  `password-salt`, `admin-password`, `api-key`, `tls-cert`, `tls-key`, `ca`); an unset reference stops
  the run, naming it, before anything is written. Everything secret reaches the containers through
  0600 env_files, never the compose file; the worker holds no administrator credential.
- Health: five healthy containers, the database answers, and the API over verified TLS refuses a call
  with no key, answers the ping with the key and reports the pinned version. The key reaches curl on
  its standard input.
- Export (pg_dump plus the datastore's tar, sha256 listing), backup, a checked restore that replaces
  (a final delta can follow a freeze), upgrade that refuses an older or foreign image, install and
  remove playbooks.
- Proved against the real images: a fresh install and health, a dump restored over the running
  database, and the archived 2.4.27 dump of an earlier instance restored and migrated forward by 2.4.29.
- Core additions: the `case-management` slot (`examples/modules/slots.yml`), its capability class
  (`record-write`), the shared read-only probe `homelabnext.conform.adapters.case_management`, pin
  freshness entries for the four images.
- The first administrator's password never lands in the app's log: a throwaway on the first start, the real one set through the API, the app force-recreated without it, a marker in the data root.
- Restore takes a safety export (`pre-restore-*`) over a populated database and refuses a source from a newer product version (`version.txt`, listed and hashed).
- MISP enrichment (option `dfir_iris_intel_enabled`, off by default): the product's bundled MISP module is registered when missing, given its settings through the administration API (the platform's HTTPS URL, a DEDICATED account's key `dfir-iris/threat-intel-key`, the CA the platform's certificate is checked against, mounted read-only into the app and the worker), its triggers set (on create by default, on update off, manual always) and enabled. A second run changes nothing; health fails when the module is not configured and enabled. The module prefers the `threat-intel` capability, so the egress to the platform follows the selection.
