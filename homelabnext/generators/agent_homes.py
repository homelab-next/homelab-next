# SPDX-License-Identifier: Apache-2.0
"""Agent homes (``HERMES_HOME``) and the orchestration controller's backend list, held to the
role table and the gateway spec (docs/orchestration-controller.md, "Model calls through the
gateway").

With the gateway in front of the engines, a backend of the controller is three things that must
agree: the controller's backend entry (the ``local`` and ``local_fallback`` entries under
``backends`` and each of its ``additional`` list: a ``name`` and its ``max_context``), the ``HERMES_HOME`` that runs
the sessions it admits (``<home>/config.yaml``, whose ``model.default`` is a role alias), and the
role table, where that role is bound to the backend's ``svc:``.  Two checks:

* :func:`controller_problems` (``hnx gen gateway render SPEC OUT --check``, when the spec has a
  ``controller:`` block): every controller backend ``name`` is a ``svc:`` of the gateway spec, its
  home's ``model.default`` is a role bound to that backend and to no other, and its ``max_context`` equals the
  role's ``max_context_tokens``.  The controller config is read as the controller reads it; which
  home belongs to which backend is the spec's ``controller.homes`` (one home per local backend,
  so the controller still decides where a session lands).
* :func:`home_findings` (``hnx gen gateway homes``, invariant A-14): a home's ``config.yaml``
  names no IP address and no engine model id.  An *engine model id* is what an engine itself
  answers to: a binding's ``model_id`` in the role table (the engine's ``--served-model-name``
  and the id the gateway sends upstream, docs/model-serving.md) and, with a model store, an
  entry's ``served_model_name`` and its hub repository (``source.repo``, which an engine loads
  directly).  A role alias is not one, even where it happens to be spelled like one: the home is
  exactly where a role must be named.  An address is found with the repository gate's own
  detection (``tools/no_raw_endpoints.py``) and :mod:`ipaddress`, documentation ranges
  included: a home names the gateway by its name, never by an address.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from homelabnext._yaml import UniqueKeyLoader
from homelabnext.registry.models import RoleTable, RoleTableError

__all__ = [
    "HOME_FILE",
    "ControllerRef",
    "controller_backends",
    "controller_problems",
    "engine_model_ids",
    "home_findings",
    "ip_literals",
    "main",
    "parse_controller",
]

HOME_FILE = "config.yaml"
#: the controller's single-entry backend slots; ``additional`` is a list of entries
BACKEND_SLOTS = ("local", "local_fallback")


@dataclass(frozen=True)
class ControllerRef:
    """A gateway spec's ``controller:`` block, its paths resolved against the spec."""

    config: Path
    homes: dict[str, Path] = field(default_factory=dict)  # backend name -> HERMES_HOME


def parse_controller(raw: Any, base: Path, problems: list[str]) -> ControllerRef | None:
    """``controller: {config: FILE, homes: {BACKEND: DIR}}``, or None (with problems)."""
    if not isinstance(raw, Mapping) or set(raw) - {"config", "homes"}:
        problems.append("controller takes config (the controller's config file) and homes")
        return None
    cfg = raw.get("config")
    if not isinstance(cfg, str) or not cfg:
        problems.append("controller.config: the controller's config file is required")
        return None
    homes: dict[str, Path] = {}
    raw_homes = raw.get("homes") or {}
    if not isinstance(raw_homes, Mapping):
        problems.append("controller.homes: a mapping of backend name to HERMES_HOME directory")
        raw_homes = {}
    for name, d in raw_homes.items():
        if not isinstance(d, str) or not d:
            problems.append(f"controller.homes.{name}: a HERMES_HOME directory")
            continue
        homes[str(name)] = base / d
    return ControllerRef(base / cfg, homes)


def _load(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)


def controller_backends(doc: Any) -> tuple[list[tuple[str, Mapping[str, Any]]], list[str]]:
    """``[(where, entry)]`` for every local backend of a controller config, and problems.

    The ``cloud`` entry is not one: it is the controller's whole-session cloud re-run, which the
    gateway reaches through a cloud-allowed role on a cloud home, not a backend of its own."""
    problems: list[str] = []
    backends = doc.get("backends") if isinstance(doc, Mapping) else None
    if not isinstance(backends, Mapping):
        return [], ["the controller config has no backends mapping"]
    out: list[tuple[str, Mapping[str, Any]]] = []
    for slot in BACKEND_SLOTS:
        if backends.get(slot) is not None:
            out.append((f"backends.{slot}", backends[slot]))
    extra = backends.get("additional") or []
    if not isinstance(extra, list):
        problems.append("backends.additional must be a list")
        extra = []
    out += [(f"backends.additional[{i}]", e) for i, e in enumerate(extra)]
    good: list[tuple[str, Mapping[str, Any]]] = []
    for where, e in out:
        if not isinstance(e, Mapping) or not isinstance(e.get("name"), str) or not e["name"]:
            problems.append(f"{where}: a backend entry needs a name")
            continue
        good.append((where, e))
    if not good and not problems:
        problems.append("the controller config declares no local backend")
    return good, problems


def _home_model(home: Path) -> tuple[Any, str | None]:
    """``(model.default, problem)`` of ``<home>/config.yaml``."""
    path = home / HOME_FILE
    try:
        doc = _load(path)
    except OSError as exc:
        return None, f"cannot read {path}: {exc.strerror or exc}"
    except (yaml.YAMLError, ValueError, RecursionError) as exc:  # ValueError: not UTF-8
        return None, f"{path} is not YAML text: {exc}"
    model = doc.get("model") if isinstance(doc, Mapping) else None
    if not isinstance(model, Mapping) or not isinstance(model.get("default"), str):
        return None, f"{path} has no model.default"
    return model["default"], None


def controller_problems(spec: Any) -> list[str]:
    """What breaks the controller-backend <-> home <-> role agreement (empty = clean).

    ``spec`` is a loaded gateway spec (:class:`homelabnext.generators.llm_gateway.Spec`) with a
    ``controller`` reference; without one there is nothing to check."""
    ref: ControllerRef | None = getattr(spec, "controller", None)
    if ref is None:
        return []
    where_cfg = ref.config.as_posix()
    try:
        doc = _load(ref.config)
    except (OSError, yaml.YAMLError, ValueError, RecursionError) as exc:
        return [f"controller config {where_cfg}: cannot read: {exc}"]
    entries, problems = controller_backends(doc)
    problems = [f"controller config {where_cfg}: {p}" for p in problems]
    names = [str(e["name"]) for _, e in entries]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        problems.append(f"controller backend {dup} is declared twice")
    for where, e in entries:
        name = str(e["name"])
        head = f"controller backend {name} ({where})"
        if name not in spec.backends:
            problems.append(
                f"{head}: svc:{name} is not a backend of the gateway spec, so no role can be "
                "bound to it"
            )
            continue
        home = ref.homes.get(name)
        if home is None:
            problems.append(f"{head}: no HERMES_HOME under the spec's controller.homes")
            continue
        default, why = _home_model(home)
        if why:
            problems.append(f"{head}: {why}")
            continue
        role = spec.table.roles.get(default)
        if role is None:
            problems.append(
                f"{head}: its home's model.default {default!r} is not a role of the role table "
                "(a home names a role alias, never an engine model id)"
            )
            continue
        bound = sorted({b.backend for b in role.bindings})
        if bound != [name]:
            why = (
                "so its sessions would run elsewhere"
                if name not in bound
                else "so the gateway would pick the engine per request and move a session "
                "between engines turn by turn"
            )
            problems.append(
                f"{head}: its home's role mdl:{default} is not bound to svc:{name} alone (bound "
                f"to {', '.join('svc:' + b for b in bound)}), {why}"
            )
            continue
        ctx, want = e.get("max_context"), role.max_context_tokens
        if isinstance(ctx, bool) or ctx != want:
            problems.append(
                f"{head}: max_context {ctx!r} differs from mdl:{default}'s max_context_tokens "
                f"{want!r}; admission and min_context affinity would judge another context"
            )
    known = set(names)
    for name in sorted(set(ref.homes) - known):
        problems.append(f"controller.homes.{name}: names no backend of the controller config")
    return problems


# ---------------------------------------------------------------------------- homes (A-14)
class CouldNotMeasure(Exception):
    """A home's file exists but cannot be read as YAML text (A-14 exits 100: neither a pass
    nor a finding)."""


def _gate_scanner() -> Any:
    """``scan_text`` of the repository gate (:mod:`homelabnext.endpoint_gate`), or None outside
    a checkout, where :func:`ip_literals` uses only its own word scan."""
    from homelabnext import endpoint_gate

    mod = endpoint_gate.load("the agent home check")
    return mod.scan_text if mod is not None else None


#: what separates the words :func:`ip_literals` reads on its own: whitespace, ``key=value``,
#: ``user@host``, list and quote punctuation
_WORD_SEPARATORS = "\t\n\r =@,;'\"()<>"


def _words(text: str) -> list[str]:
    out, cur = [], []
    for ch in text:
        if ch in _WORD_SEPARATORS:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _address(token: str) -> str | None:
    """``token`` (a value, a word, or a URL) read as an IP address, or None."""
    t = token.strip().strip("'\"()<>").rstrip(",;")
    if "://" in t:
        try:
            host = urlsplit(t).hostname or ""
        except ValueError:
            return None
    elif t.startswith("["):  # [v6] or [v6]:port
        host = t[1 : t.find("]")] if "]" in t else t[1:]
    elif t.count(":") == 1:  # host:port
        host = t.split(":", 1)[0]
    else:
        host = t
    host = host.split("%", 1)[0].split("/", 1)[0]  # a zone id, a prefix length
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def ip_literals(text: str) -> list[str]:
    """Every IP address ``text`` names: the gate's IPv4 rule and the hosts of its URL rules, and
    each word or URL that :mod:`ipaddress` reads as an address (IPv6 included; words split at
    whitespace, ``=``, ``@`` and punctuation, so ``host=<addr>`` and ``user@<addr>`` are found
    with or without the gate).  Documentation and
    loopback addresses count: a home should name no address at all."""
    found: list[str] = []
    scan = _gate_scanner()
    if scan is not None:
        for f in scan("home", text):
            addr = f.text if f.rule == "ipv4" else _address(f.text)
            if addr and addr not in found:
                found.append(addr)
    for word in _words(text):
        addr = _address(word)
        if addr and addr not in found:
            found.append(addr)
    return found


def engine_model_ids(table: RoleTable, store: Mapping[str, Any] | None = None) -> set[str]:
    """The ids an engine answers to (see the module docstring), minus the role aliases."""
    ids = {b.model_id for r in table.roles.values() for b in r.bindings}
    models = (store or {}).get("models") if isinstance(store, Mapping) else None
    for entry in (models or {}).values():
        if not isinstance(entry, Mapping):
            continue
        if isinstance(entry.get("served_model_name"), str):
            ids.add(entry["served_model_name"])
        repo = (entry.get("source") or {}).get("repo")
        if isinstance(repo, str):
            ids.add(repo)
    return {i for i in ids if i} - set(table.roles)


def _strings(node: Any) -> Iterator[tuple[str, str, bool]]:
    """``(where, text, is_key)`` for every string in a YAML document, keys included.  Each
    container is visited once, so an alias that refers back to its own node (``a: &x [*x]``)
    ends instead of recursing."""
    seen: set[int] = set()
    stack: list[tuple[Any, str]] = [(node, "")]
    while stack:
        cur, path = stack.pop()
        if isinstance(cur, (Mapping, list)):
            if id(cur) in seen:
                continue
            seen.add(id(cur))
        if isinstance(cur, Mapping):
            items = list(cur.items())
            for k, v in reversed(items):
                sub = f"{path}.{k}" if path else str(k)
                stack.append((v, sub))
                stack.append((_Key(str(k)), sub))
        elif isinstance(cur, list):
            for i in range(len(cur) - 1, -1, -1):
                stack.append((cur[i], f"{path}[{i}]"))
        elif isinstance(cur, _Key):
            yield path, cur.text, True
        elif isinstance(cur, str):
            yield path, cur, False


class _Key:
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _names_id(value: str, ids: Iterable[str]) -> str | None:
    """The engine model id ``value`` names, compared without case: the id itself, the id behind a
    provider prefix (``openai/<id>``), or either with a ``:tag`` or ``@quant`` suffix."""
    forms = {value.strip().lower()}
    for sep in (":", "@"):
        forms |= {f.split(sep, 1)[0] for f in forms if sep in f}
    for i in sorted(ids, key=len, reverse=True):
        il = i.lower()
        if any(f == il or f.endswith("/" + il) for f in forms):
            return i
    return None


def home_findings(home: Path, ids: set[str]) -> list[str]:
    """What ``<home>/config.yaml`` names that it must not (empty = clean).  A missing file is a
    finding (nothing to check never reads as checked); a file that is not UTF-8 or not YAML raises
    :class:`CouldNotMeasure`."""
    path = home / HOME_FILE
    try:
        doc = _load(path)
    except UnicodeDecodeError as exc:
        raise CouldNotMeasure(
            f"{path}: not UTF-8 text ({exc.reason} at byte {exc.start})"
        ) from None
    except OSError as exc:
        return [f"{path}: cannot read: {exc.strerror or exc}"]
    except (yaml.YAMLError, RecursionError) as exc:
        raise CouldNotMeasure(f"{path}: not readable as YAML: {exc}") from None
    out: list[str] = []
    for where, value, is_key in _strings(doc):
        for addr in ip_literals(value):
            out.append(f"{path}: {where} names the IP address {addr} (name the gateway instead)")
        mid = None if is_key else _names_id(value, ids)  # a key is a field name, not a model
        if mid:
            out.append(
                f"{path}: {where} names the engine model id {mid!r} (name its role alias; the "
                "role table maps it to the model)"
            )
    return out


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx gen gateway homes",
        description="Fail when an agent home's config.yaml names an IP address or an engine "
        "model id (invariant A-14)",
    )
    ap.add_argument("homes", nargs="+", help="HERMES_HOME directories (each holds config.yaml)")
    ap.add_argument("--roles", required=True, help="the role table (model_roles.json)")
    ap.add_argument("--store", help="a model store manifest, for its served names and repos")
    args = ap.parse_args(list(argv) if argv is not None else None)
    try:
        table = RoleTable.load(args.roles)
        store = json.loads(Path(args.store).read_text(encoding="utf-8")) if args.store else None
    except (OSError, ValueError, RoleTableError) as exc:
        print(f"homes: cannot read the role table or store: {exc}", file=sys.stderr)
        return 2
    ids = engine_model_ids(table, store)
    if _gate_scanner() is None:
        print(
            "homes: warning: not a homelabnext checkout, so tools/no_raw_endpoints.py is not "
            "loaded; addresses are found by the word scan only",
            file=sys.stderr,
        )
    findings: list[str] = []
    try:
        for h in args.homes:
            findings += home_findings(Path(h), ids)
    except CouldNotMeasure as exc:
        print(f"homes: could not measure: {exc}", file=sys.stderr)
        return 100
    for f in findings:
        print(f"homes: {f}", file=sys.stderr)
    if findings:
        return 1
    print(f"homes: {len(args.homes)} home(s) name no IP address and no engine model id")
    return 0
