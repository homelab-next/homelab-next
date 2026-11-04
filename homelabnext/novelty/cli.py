# SPDX-License-Identifier: Apache-2.0
"""``hnx novelty``: run the behavioural novelty analyzer and corroborate its findings
(ADR-0035; docs/novelty.md).

``hnx novelty run --spec FILE --as-of ISO --site SITE [--dry-run] [--show-findings] LAKE``
scores every profile for ``as_of`` and, unless ``--dry-run``, writes the rows to
``novelty_finding``; it prints the run summary (per profile: status ``ok``, ``warming`` or
``failed``, the windows, the oldest day found and the days of history, what was emitted and
dropped) as JSON.  ``hnx novelty corroborate --since ISO --until ISO --site SITE
[--min-sources N] LAKE`` prints the entities that at least two distinct sources flagged.

The analyzer reads as ``analyzer:novelty`` at the ceiling ``SITE``'s ``tlp_readers`` declares
for it (a site that declares none: refused).  ``LAKE`` is either ``--fixture FILE`` (a YAML or
JSON mapping of table name to rows, loaded into the in-memory fake lake: examples and tests) or
``--domain D --namespace NS --warehouse WH`` (the lab's ``lake-query`` and ``lake-catalog``
endpoints, resolved from the registry's domain, signing in as ``analyzer:novelty``).  There is
no clock: ``--as-of`` is required, so a run is replayable.

Exit: 0 done, 1 a profile failed, 2 usage, spec, site or lake error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

__all__ = ["main"]


def _when(text: str) -> datetime:
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 time: {text!r}") from None
    if t.utcoffset() is None:
        raise argparse.ArgumentTypeError(f"{text!r} has no UTC offset (write Z or +00:00)")
    return t


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx novelty", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def lake_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--site", required=True, help="the site (lab/modules.yml): tlp_readers")
        src = p.add_mutually_exclusive_group(required=True)
        src.add_argument("--fixture", help="YAML/JSON {table: [rows]} loaded into the fake lake")
        src.add_argument("--domain", help="the registry domain the lake endpoints resolve under")
        p.add_argument("--namespace", help="with --domain: the lake namespace (default ocsf)")
        p.add_argument("--warehouse", help="with --domain: the catalog's warehouse")

    run = sub.add_parser("run", help="score every profile of a spec for --as-of")
    run.add_argument("--spec", required=True, help="the novelty spec (YAML or JSON)")
    run.add_argument("--as-of", required=True, type=_when, help="end of the scoring window")
    run.add_argument("--dry-run", action="store_true", help="score, but write nothing")
    run.add_argument("--show-findings", action="store_true", help="print the rows too")
    lake_args(run)

    cor = sub.add_parser("corroborate", help="entities flagged by >= 2 distinct sources")
    cor.add_argument("--since", required=True, type=_when, help="window start (inclusive)")
    cor.add_argument("--until", required=True, type=_when, help="window end (exclusive)")
    cor.add_argument("--min-sources", type=int, default=2, help="distinct sources (>= 2)")
    lake_args(cor)
    return ap


class _Usage(Exception):
    pass


def _load(path: str) -> Any:
    p = Path(path)
    try:
        if p.suffix == ".json":
            return json.loads(p.read_text(encoding="utf-8"))
        from homelabnext._yaml import load_unique

        return load_unique(p, _Usage)
    except (OSError, ValueError) as exc:
        raise _Usage(f"cannot read {p}: {exc}") from exc


def _lake(args: argparse.Namespace, schemas: Any) -> Any:
    from homelabnext.novelty import READER

    if args.fixture:
        from homelabnext.lake import FakeLake

        doc = _load(args.fixture)
        if not isinstance(doc, dict):
            raise _Usage(f"{args.fixture}: a fixture is a mapping of table name to rows")
        lake = FakeLake(schemas)
        for table, rows in sorted(doc.items()):
            lake.write_batch(table, rows, idempotency_key=f"fixture:{table}")
        return lake
    if not args.warehouse:
        raise _Usage("--domain needs --warehouse")
    from homelabnext.conform.adapters.lake import make_lake

    return make_lake(
        domain=args.domain,
        namespace=args.namespace or "ocsf",
        warehouse=args.warehouse,
        user=READER,
    )


def _reader(args: argparse.Namespace) -> tuple[Any, Any, Any]:
    from homelabnext.lake import load_schemas
    from homelabnext.lake.ceiling import reader_for
    from homelabnext.novelty import READER

    site = _load(args.site)
    readers = site.get("tlp_readers") if isinstance(site, dict) else None
    if not isinstance(readers, list):
        raise _Usage(f"{args.site}: no tlp_readers list, so {READER} has no ceiling")
    schemas = load_schemas()
    lake = _lake(args, schemas)
    return reader_for(lake, READER, readers, schemas), lake, schemas


def _json(doc: Any) -> str:
    def default(v: Any) -> Any:
        if isinstance(v, datetime):
            return v.isoformat().replace("+00:00", "Z")
        raise TypeError(type(v).__name__)

    return json.dumps(doc, indent=2, sort_keys=True, default=default)


def _run(args: argparse.Namespace) -> int:
    from homelabnext.novelty import SOURCE, load_spec, run

    reader, lake, schemas = _reader(args)
    spec = load_spec(args.spec, schemas)
    results = run(reader, spec, args.as_of, writer=None if args.dry_run else lake)
    doc: dict[str, Any] = {
        "as_of": args.as_of,
        "source": SOURCE,
        "spec_digest": spec.digest,
        "dry_run": args.dry_run,
        "profiles": [r.summary() for r in results],
    }
    if args.show_findings:
        doc["findings"] = [row for r in results for row in r.rows]
    print(_json(doc))
    return 1 if any(r.status == "failed" for r in results) else 0


def _corroborate(args: argparse.Namespace) -> int:
    from homelabnext.novelty import TABLE, corroborate

    reader, _, _ = _reader(args)
    groups = reader.count_by(
        TABLE, "entity", ["source", "profile", "status"], since=args.since, until=args.until
    )
    rows = [
        {
            "entity": g.entity,
            "source": g.values[0],
            "profile": g.values[1],
            "status": g.values[2],
            "tlp": g.label.value,
            "rows": g.count,
        }
        for g in groups
    ]
    found = corroborate(rows, min_sources=args.min_sources)
    print(
        _json(
            {
                "since": args.since,
                "until": args.until,
                "candidates": [c.as_dict() for c in found],
            }
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    from homelabnext.lake.errors import LakeError
    from homelabnext.novelty import SpecError

    try:
        return _run(args) if args.cmd == "run" else _corroborate(args)
    except (_Usage, SpecError, LakeError, ValueError) as exc:
        print(f"hnx novelty: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
