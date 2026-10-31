# homelabnext.lake

Query, catalog and idempotent write for the lake capabilities (`lake-query`, `lake-catalog`).
`import homelabnext.lake` needs only the standard library; heavy dependencies are the `lake`
extra (`pip install 'homelabnext[lake]'` = duckdb, pyarrow, pyiceberg with SQL catalog and
`pyiceberg-core`) and the `trino` extra, imported lazily with a clear `MissingExtra` error.

## Interface (`protocol.py`)

```python
class LakeClient(Protocol):          # LakeQuery + LakeWriter + the rest
    def query(self, sql, params=None) -> list[dict]
    def named(self, name, params=None) -> list[dict]
    def describe(self, table) -> TableInfo            # columns, key, row_count, committed marks
    def write_batch(self, table, rows, *, idempotency_key, source=None, high_water=None) -> WriteResult
    def write(self, table, rows, *, batch_id) -> int  # interfaces.md alias
    def list_tables(self) -> list[str]
```

| Implementation | Needs | Use |
|---|---|---|
| `FakeLake` | stdlib (sqlite3) | unit tests, the second implementation for the swap kit |
| `DuckDBLake` | duckdb, pyarrow | read-only parity reference over Arrow tables |
| `IcebergLake` | pyiceberg, pyarrow, duckdb | catalog-backed read/write (SQL catalog locally, REST via the registry) |
| `TrinoLake` | trino, SERVER | `lake-query` client: UTC session, TLS verified, no remote plaintext |
| `CassetteLake` | stdlib | replays recorded results; `compare()` is the parity primitive |

SQL is a portable subset (`:name` parameters; joins, group/having/order/limit, CTE, CASE,
COALESCE, ROUND, LIKE, IN; timestamps compared with `'YYYY-MM-DD HH:MM:SS'` UTC literals). Struct
field access and engine-specific functions are outside it. Results are compared through
`normalize_result_rows`.

## Idempotent write: commit, then checkpoint (`checkpoint.py`)

Encodes a real incident: a writer committed a batch, crashed before saving its read offset and,
restarted, replayed a rotated log tail from the stale offset, duplicating every row.

1. The lake commit is first, the checkpoint second, so a crash leaves the checkpoint behind the
   lake, never ahead of it.
2. The batch id, source and high-water mark are stored **inside the lake commit** (Iceberg
   snapshot summary `hnx.batch-id`, `hnx.source`, `hnx.high-water`; a ledger row committed in the
   same transaction in `FakeLake`). The checkpoint (a `homelabnext.state` file: atomic, locked,
   versioned; the older `{"version": 1, "sources"}` file is still read) records the committed
   batch id, snapshot id and position. `Ingestor.start()` sees a lake mark newer than the checkpoint and fast-forwards.
3. If the tail is read again anyway (lost checkpoint, expired snapshots, different batching),
   rows whose content key (`uid`) already exist are skipped. Replay is idempotent.

One writer per `(table, source)` is assumed.

## Safety rules

* Whole batch validated before any write; naive timestamps, unknown columns, wrong types refused.
* Every row carries its TLP label (ADR-0033 decision 5): a table with the `tlp` column (every OCSF
  table from 1.1) refuses a batch with any row whose label is missing or not one of the five
  canonical spellings. The writer normalises with `homelabnext.tlp` first; the lake stores one
  spelling. The column is optional in the schema, so a row stored before it existed stays valid.
  `tables.row_label` reads only a canonical stored value as its label; a row without one, or with
  any other value (an alternate spelling such as `white` or `Green` that a writer bypassing the
  lake stored, a damaged value), is `red`. Until the backfill migration exists, a swap cannot
  shadow-start from a lake whose rows predate the column: the copy is refused, as any write
  without a label is.
* The one-off TLP backfill of rows stored before the column (ADR-0033 decision 5) is a plan, never
  an execution: `backfill.plan` (and `hnx modules tlp-backfill`, from render's
  `tlp-sources.json`) prints the statements in order. It adds the column, labels a row by its
  recorded source's declaration (`red` for a source whose items' own labels were never stored),
  gives every other row the strictest source's label, and touches only rows still unlabelled, so a
  second run changes nothing.
* An existing table that differs from the generated schema raises `SchemaMismatch`; nothing is written.
* Endpoints come from `homelabnext.registry`; an unset endpoint raises `EndpointNotConfigured`.
  There is no literal default.
