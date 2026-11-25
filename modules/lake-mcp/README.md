<!-- SPDX-License-Identifier: Apache-2.0 -->
# lake-mcp: the read-only lake MCP server

`hnx lake mcp` (`homelabnext/lake/mcp_tools.py`, catalog id `hnx-lake`,
`examples/mcp/hnx-lake.yml`) is how an agent reads the lake (ADR-0030: reads go through a
read-only MCP server, actions through the broker). This module installs it on a guest the site
picks and lets a client start it over SSH stdio with a key that can run nothing else.

## What it serves

| Tool | Does |
|---|---|
| `list_tables(schema?)` | the tables of the allowed schemas (`information_schema`), as `schema.table` |
| `describe_table(table)` | one table's columns, types and nullability |
| `query(sql, params?, max_rows?)` | ONE `SELECT` (or `WITH ... SELECT`) with `:name` parameters bound by the engine; at most `max_rows` rows (`truncated` says when there were more; the query is cancelled), a client deadline and the engine's own `query_max_execution_time` |

Every tool is a read (`classes: [read]`, `readOnlyHint`). Nothing a tool call carries picks the
account, the endpoint, the catalog or a credential.

## Why it cannot write

Three layers, outermost first:

1. **The gate** (`homelabnext/lake/readonly.py`, `select_only`): the first keyword is `SELECT` or
   `WITH`; one statement (a `;` outside a literal or comment is refused); no bare write verb
   anywhere (`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `CREATE`, `DROP`, `ALTER`, `CALL`, `EXECUTE`,
   `GRANT`, `TRUNCATE`, ...: a column of such a name is quoted). `SHOW`, `EXPLAIN` (whose `ANALYZE`
   form runs its statement) and session statements are refused too. Nothing refused is sent.
2. **Its own reader**: the server signs in as the account `lake_mcp_lake_user` with its own
   password (`secret:lake-mcp/reader-password`, an owner-only file on the guest; the client never
   sees it). The engine's access rules give that account `SELECT` on the schemas the site names
   and nothing else, and an unknown user nothing at all.
3. **A read-only catalog** (`lake_mcp_catalog`): point it at a catalog the engine itself holds
   read-only (modules/trino `trino_reader_catalog`, `iceberg.security=read-only`). That refuses
   every write AND every table procedure (`ALTER TABLE ... EXECUTE`), whoever asks; the engine's
   file rules alone never see a table procedure, so a read grant on a writable catalog is not
   enough to rule them out.

## The SSH stdio placement

The client (an agent's MCP configuration) runs `ssh -i <key> <account>@<guest>`, and the guest's
`authorized_keys` line for that key is

```
restrict,command="/opt/hnx/bin/hnx lake mcp --config /etc/hnx-modules/lake-mcp/lake-mcp.yml"[,from="<client>"] <key>
```

`restrict` turns off the pty, port, agent and X11 forwarding and the user rc; the forced command
ignores whatever the client asks to run. So the client's machine needs a route to the guest's SSH
port only, not to the query engine, and the key opens nothing but the server.

## What the overlay adds

- a placement: `slots`/`features` selection of `lake-mcp` with its `server` role on a guest that
  can reach the `lake-query` endpoint and runs the runtime release **with the `mcp` extra**
  (role `hnx_runtime`, `hnx_runtime_extras` including `mcp`);
- `group_vars/mod_lake_mcp_server.yml`: `lake_mcp_catalog` (required), `lake_mcp_schemas`
  (required), `lake_mcp_authorized_keys` (the client's public key), `lake_mcp_ssh_from` (the
  client's address), `lake_mcp_ca_ref` (the lab CA, when the engine's certificate is private),
  and `lake_mcp_lake_user` when the engine account is not `lake-mcp`;
- the secret `lake-mcp/reader-password` (a generated password) and its bcrypt line in the
  engine's password file;
- the engine's access rules: `SELECT` for that account on exactly the schemas it may read, on
  the read-only catalog, and no other privilege;
- nothing in the firewall for the engine: the server runs beside the engine's other readers.

## Health

`health` checks the files and modes, that every key line is restricted to the forced command, and
runs `hnx lake mcp --config <settings> --check` as the service account: it signs in, lists the
allowed tables and exits (0 ok, 2 bad settings or no MCP SDK, 100 the engine could not be read).

## Lifecycle

No data of its own: `backup`, `export` and `restore` say so; `upgrade` proves the installed
release answers `hnx lake mcp` and records it; `remove` deletes the keys first, then the settings
and the credential.
