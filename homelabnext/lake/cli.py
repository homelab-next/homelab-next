# SPDX-License-Identifier: Apache-2.0
"""``hnx lake``: commands over the lake.

``hnx lake source-census [--config FILE | --fixture FILE] [--criterion NAME] [--no-notify]``

runs the two criteria of the ``source-census`` module (ADR-0049 decision 9) and pages on a NEWLY
flagged set only:

* ``sources-flowing``: every source of the event table against its own cadence over the window
  (:mod:`homelabnext.lake.census`); it fails on a flagged source, passes with a warning while a
  source is still learning;
* ``all-classes-dark``: no row in any of the configured tables in the last ``dark.hours`` hours.

The settings are one YAML or JSON file (``--config``): ``lake`` (``domain``, ``warehouse``, ``catalog``,
``namespace``, ``user``, ``credential_file``, ``ca_file``), ``census`` (:func:`homelabnext.lake.
census.config_from`), ``dark`` (``tables``, ``hours``), ``notify`` (``topic``, ``token_file``,
``ceiling``) and ``state`` (the paging state file).  ``--fixture FILE`` reads ``{rows: [...]}``
into the in-memory lake instead (examples and tests); ``--now`` pins the clock.  A credential is
read from a file that only its owner may read, never from the command line.

Paging is state-diffed: the set of flagged items (a source, or the dark state) is compared with
the last run's; a message goes out only when the set GAINS a member, one more when it empties, and
a standing set is never sent again.  The state is saved after a successful send, so a failed page
is retried next run.  The titles are constant and carry no counts (the body does).

Exit: 0 every criterion passes (a warning included), 1 one failed, 2 usage or settings,
100 could not measure.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from homelabnext._cliargs import iso_when, load_doc

from .census import CensusConfig, CensusError, census, config_from, dark
from .errors import LakeError

__all__ = ["TITLE_CLEAN", "TITLE_FLAGGED", "fixture_schema", "main", "page"]

#: constant, count-free titles: the pair is contributed by the module (notify_pairs)
TITLE_FLAGGED = "Source census: source(s) flagged"
TITLE_CLEAN = "Source census: all sources flowing"
#: the secret name the engine client reads the reader's password under (set in-process from the file)
CREDENTIAL_REF = "secret:source-census/reader-password"
CRITERIA = ("sources-flowing", "all-classes-dark")


class _Usage(Exception):
    pass


def fixture_schema(table: str, source_columns: Sequence[str], time_column: str):
    """An in-memory table schema for a fixture: a unique ``uid``, the time and the source columns."""
    from .tables import Column, TableSchema

    cols = (
        Column("uid", "string", True),
        Column(time_column, "timestamp", True),
        *(Column(c, "string") for c in source_columns),
    )
    return TableSchema(
        name=table, schema_id=f"fixture/{table}", ocsf_class_uid=0, ocsf_version="0",
        columns=cols, key=("uid",), time_column=time_column, partition=f"day({time_column})",
    )  # fmt: skip


def _load(path: str) -> Any:
    return load_doc(path, _Usage)


def _secret_from_file(path: str, what: str) -> str:
    p = Path(path)
    try:
        mode = p.stat().st_mode
        text = p.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise _Usage(f"{what}: cannot read {p}: {exc.strerror or exc}") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise _Usage(
            f"{what}: {p} is readable by group or others (mode {stat.S_IMODE(mode):04o}); it must be 0600"
        )
    if not text:
        raise _Usage(f"{what}: {p} is empty")
    return text


def _lake(
    cfg: Mapping[str, Any], census_cfg: CensusConfig, tables: Sequence[str], fixture: str | None
):
    if fixture:
        from .fake import FakeLake

        doc = _load(fixture)
        rows = doc.get("rows") if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            raise _Usage(f"{fixture}: a fixture is a mapping with a rows list")
        schemas = [
            fixture_schema(t, census_cfg.source_columns, census_cfg.time_column)
            for t in dict.fromkeys(tables)
        ]
        lake = FakeLake(schemas)
        by_table: dict[str, list[dict[str, Any]]] = {}
        for i, r in enumerate(rows):
            r = dict(r)
            t = r.pop("table", census_cfg.table)
            if t not in {s.name for s in schemas}:
                raise _Usage(
                    f"{fixture}: row {i} names table {t!r}, which is not a configured table"
                )
            tc = census_cfg.time_column
            if tc not in r:
                raise _Usage(f"{fixture}: row {i} has no {tc!r}")
            r[tc] = iso_when(str(r[tc]))
            r["uid"] = f"fixture-{i}"
            by_table.setdefault(t, []).append(r)
        for t, rs in by_table.items():
            lake.write_batch(t, rs, idempotency_key=f"fixture:{t}")
        return lake
    live = cfg.get("lake") or {}
    for need in ("domain", "warehouse", "catalog", "credential_file"):
        if not live.get(need):
            raise _Usage(f"settings: lake.{need} is required (or give --fixture)")
    return _Engine(live, _secret_from_file(live["credential_file"], "lake.credential_file"))


class _Engine:
    """The census's read-only view of the lake-query endpoint: the shared engine client, signed in
    as the reader, with the catalog and namespace as its session (so a bare table name resolves).
    The census reads counts and hours only and creates nothing; the shared client factory also
    resolves the catalog endpoint, which nothing is sent to."""

    sql_dialect = "struct"

    def __init__(self, live: Mapping[str, Any], password: str) -> None:
        from homelabnext.conform.adapters._env import AdapterConfigError
        from homelabnext.conform.adapters.lake import make_clients
        from homelabnext.registry.model import secret_env_name

        os.environ[secret_env_name(CREDENTIAL_REF)] = password
        try:
            engine, _catalog = make_clients(
                domain=live["domain"],
                warehouse=live["warehouse"],
                user=live.get("user", "analyzer:source-census"),
                credential=CREDENTIAL_REF,
                ca_file=live.get("ca_file"),
            )
        except (AdapterConfigError, LakeError, LookupError, ValueError) as exc:
            raise _Usage(f"lake endpoints: {exc}") from None
        engine.catalog, engine.schema = live["catalog"], live.get("namespace", "soc")
        self._engine = engine

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        from .sqlparams import check_params, to_qmark

        text, args = to_qmark(sql, check_params(sql, params))
        return self._engine.execute(text, args).rows


def _sender(notify: Mapping[str, Any], domain: str | None):
    from homelabnext.notify import default_sender
    from homelabnext.notify.ceiling import CeilingSender, ceiling_arg
    from homelabnext.registry import Resolver

    for need in ("topic", "token_file", "ceiling"):
        if not notify.get(need):
            raise _Usage(f"settings: notify.{need} is required to page (or give --no-notify)")
    try:
        ceiling = ceiling_arg(str(notify["ceiling"]))
    except argparse.ArgumentTypeError as exc:
        raise _Usage(f"settings: notify.ceiling: {exc}") from None
    token_file = notify["token_file"]
    _secret_from_file(token_file, "notify.token_file")  # refused now, read again at send time
    if not domain:
        raise _Usage("settings: lake.domain is needed to resolve the notify endpoint")
    inner = default_sender(
        resolver=Resolver(domain=domain),
        default_topic=notify["topic"],
        auth=lambda: "Bearer " + _secret_from_file(token_file, "notify.token_file"),
    )
    return CeilingSender(inner, ceiling)


def page(flagged: Mapping[str, str], state_path: str | Path, sender: Any, *, summary: str) -> str:
    """Send at most one message for the change in the flagged set and save the state afterwards.

    ``flagged`` is ``{item: one line}``.  Returns ``paged``, ``recovered`` or ``standing``/``clear``
    (nothing sent).  A set that only shrinks (some, not all, recovered) pages nothing and is
    recorded, so the next new item is judged against what is flagged now.
    """
    from homelabnext.notify.core import Message
    from homelabnext.state import atomic_write_text

    p = Path(state_path)
    try:
        before = set(json.loads(p.read_text(encoding="utf-8")).get("flagged", []))
    except (OSError, ValueError):
        before = set()
    now = set(flagged)
    new = sorted(now - before)
    outcome = "standing" if now else "clear"
    if new:
        lines = [f"{'NEW ' if k in new else '    '}{flagged[k]}" for k in sorted(now)]
        sender.send(
            Message(
                key="source-census",
                title=TITLE_FLAGGED,
                body=summary + "\n\n" + "\n".join(lines),
                level="warn",
            )
        )
        outcome = "paged"
    elif before and not now:
        sender.send(
            Message(
                key="source-census",
                title=TITLE_CLEAN,
                body=summary,
                level="info",
                tags=("recovered",),
            )
        )
        outcome = "recovered"
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(p, json.dumps({"flagged": sorted(now)}, indent=2, sort_keys=True) + "\n")
    return outcome


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx lake", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser(
        "source-census", help="every source against its own cadence; all classes dark"
    )
    src = sc.add_mutually_exclusive_group(required=True)
    src.add_argument("--config", help="the settings file (YAML or JSON)")
    src.add_argument(
        "--fixture", help="{rows: [...]} loaded into the in-memory lake (examples, tests)"
    )
    sc.add_argument("--settings", help="with --fixture: the settings file (census, dark)")
    sc.add_argument("--criterion", choices=("all", *CRITERIA), default="all")
    sc.add_argument(
        "--now", type=iso_when, help="the clock (ISO 8601 with offset); default the real time"
    )
    sc.add_argument("--state", help="the paging state file (overrides settings state)")
    sc.add_argument(
        "--no-notify", action="store_true", help="evaluate and print; page nobody, keep no state"
    )
    return ap


def _source_census(
    ns: argparse.Namespace,
    *,
    sender_for: Callable[..., Any] = _sender,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    from .ceiling import RedGrant, raw_query

    cfg = _load(ns.config or ns.settings) if (ns.config or ns.settings) else {}
    if not isinstance(cfg, dict):
        raise _Usage("the settings are a mapping")
    census_cfg = config_from(cfg.get("census") or {})
    dark_cfg = cfg.get("dark") or {}
    dark_tables = list(dark_cfg.get("tables") or [census_cfg.table])
    dark_hours = float(dark_cfg.get("hours", 24))
    lake = _lake(cfg, census_cfg, [census_cfg.table, *dark_tables], ns.fixture)
    grant = RedGrant(
        "source-census", "counts and last-seen hours only; no row content is read or kept"
    )
    run = lambda sql, params: raw_query(lake, grant, sql, params)  # noqa: E731
    now = ns.now or clock()
    wanted = CRITERIA if ns.criterion == "all" else (ns.criterion,)

    flagged: dict[str, str] = {}
    worst = 0
    summary: list[str] = []
    try:
        if "sources-flowing" in wanted:
            rep = census(run, lake, census_cfg, now=now)
            verdict = {"fail": "FAIL", "warn": "WARN", "pass": "pass"}[rep.status]
            print(f"{verdict:5s} source-census/sources-flowing  {rep.evidence()}")
            summary.append(rep.evidence().splitlines()[0])
            for r in rep.flagged:
                flagged[r.key] = f"[{r.status}] {r.name}: {r.detail}"
            if not rep.results:
                flagged["sources-flowing"] = "no source arrived in the window"
            worst = max(worst, 1 if rep.status == "fail" else 0)
        if "all-classes-dark" in wanted:
            d = dark(
                run, dark_tables, now=now, hours=dark_hours, time_column=census_cfg.time_column
            )
            print(
                f"{'FAIL' if d.dark else 'pass':5s} source-census/all-classes-dark  {d.evidence()}"
            )
            summary.append(d.evidence())
            if d.dark:
                flagged["all-classes-dark"] = d.evidence()
                worst = 1
    except (CensusError, LakeError) as exc:
        print(f"[source-census] could not measure: {exc}", file=sys.stderr)
        return 100

    state = ns.state or cfg.get("state")
    if not ns.no_notify and state and (cfg.get("notify") or {}) and ns.criterion == "all":
        sender = sender_for(cfg["notify"], (cfg.get("lake") or {}).get("domain"))
        outcome = page(flagged, state, sender, summary="\n".join(summary))
        print(f"[source-census] paging: {outcome}")
    return worst


def main(argv: Sequence[str] | None = None) -> int:
    ns = _parser().parse_args(argv)
    try:
        if ns.cmd == "source-census":
            return _source_census(ns)
    except _Usage as exc:
        print(f"hnx lake: {exc}", file=sys.stderr)
        return 2
    except CensusError as exc:
        print(f"hnx lake: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # a failed page or send: the verdict is undelivered, never a pass
        from homelabnext.notify.core import SendError

        if isinstance(exc, SendError):
            print(f"hnx lake: the page was not delivered: {exc}", file=sys.stderr)
            return 100
        raise
    return 2


if __name__ == "__main__":
    sys.exit(main())
