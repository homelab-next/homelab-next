<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: module `openproject`

## 0.1.0 (unreleased)

- First version: the `projects` provider on OpenProject 15.5.1 (the slim image: web app and
  worker as two containers of one pinned image), PostgreSQL 17.10 and a memcached cache, all
  pinned by tag and digest, as `compose_app` containers in the module's slice. Plain http on the
  guest's own address for the edge; the database and the cache publish no port.
- Local accounts (`auth: own`): the route is public only through the edge and is not behind the
  single sign-on. The edge sets `X-Forwarded-Proto: https`; the app is told `https` and its public
  name.
- The product's seeder (migrations, then seed) runs as a one-off against the image about to serve,
  before the app opens the database; it runs again only when the image changes or a restore asks.
- Credentials by `secret:` name (`openproject/db-password`, `openproject/secret-key-base`,
  `openproject/admin-password`); an unset reference stops the run, naming it, before anything is
  written.
- Health: the four containers healthy, the database answers, the app's default and database
  health checks give 200.
- Export (pg_dump plus the attachments' tar, sha256 listing), backup, a checked restore (the web
  app and the worker stopped, one transaction, the attachments replaced) that can be run again
  for a final delta, and the generic migration tool `tools/migrate/openproject.py`.
