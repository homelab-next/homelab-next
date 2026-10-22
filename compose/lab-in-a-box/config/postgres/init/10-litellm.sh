#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Runs once, when the postgres image initialises an empty data volume
# (/docker-entrypoint-initdb.d).  The LLM gateway (LiteLLM, profile `gateway`) gets its own login
# role that owns only the `litellm` schema of the catalog database: it cannot create anything in
# `public` (postgres 15+ grants PUBLIC no CREATE there) and has no privilege on the catalog's own
# tables, so a compromised gateway cannot touch the lake catalog.  The password comes from the
# lab's .env (LAB_GATEWAY_DB_PASSWORD), like every other lab credential.  An existing volume
# keeps its state: `docker compose down -v` (or create the role by hand) to pick this up.
set -eu
: "${LAB_GATEWAY_DB_PASSWORD:?LAB_GATEWAY_DB_PASSWORD is not set (see .env.example)}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v gateway_password="$LAB_GATEWAY_DB_PASSWORD" <<'SQL'
CREATE ROLE litellm LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'gateway_password';
CREATE SCHEMA litellm AUTHORIZATION litellm;
REVOKE CREATE ON SCHEMA public FROM litellm;
ALTER ROLE litellm IN DATABASE :"DBNAME" SET search_path = litellm;
SQL
