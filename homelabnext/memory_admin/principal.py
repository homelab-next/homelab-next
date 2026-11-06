# SPDX-License-Identifier: Apache-2.0
"""Who may run ``MemoryAdmin`` (ADR-0037 decision 12): an :class:`OperatorPrincipal`, built only
by the ``hnx agent memory`` command, from the invoking operating-system user.

The **operators file** is reviewed configuration, never the state file.  It is YAML or JSON::

    operators: [alice, bob]          # OS user names allowed to run hnx agent memory
    agent_runtime:                   # the users (or uids) the agent runtime runs as
      - {user: hnx-agent}
    broker:                          # the users (or uids) the broker runs as
      - {user: hnx-broker}
    broker_manifest: broker.yml      # optional: also refuse its callers and Code Mode peers

* ``agent_runtime`` and ``broker`` name the uids that are refused, whatever the operators list
  says.  The broker manifest's ``callers`` (and ``codemode`` runners and sandboxes) are the agent
  runtime's peers as the broker knows them, so ``broker_manifest`` (a path relative to this file)
  adds them; the broker's own user is configured nowhere else, so ``broker`` must list it.  At
  least one runtime user (``agent_runtime`` or the manifest's peers) and one broker user are
  required, and an operator may not be one of them.
* The file must be one the runtime cannot write: it and every directory above it are owned by
  none of the refused uids and are writable by no group or other (a directory with the sticky
  bit, such as ``/tmp``, excepted).  :func:`load_operators` refuses it otherwise.

:func:`invoking_operator` reads the real and effective uids of this process (``os.getuid``,
``os.geteuid``); either being a refused uid is refused, and the real user's name must be in
``operators``.  An :class:`OperatorPrincipal` cannot be constructed directly, subclassed or
changed.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_OPERATORS",
    "MemoryAdminError",
    "OperatorConfig",
    "OperatorPrincipal",
    "invoking_operator",
    "load_operators",
    "require_operator",
]

#: where ``hnx agent memory`` reads the operators file unless ``--operators`` names another
DEFAULT_OPERATORS = "/etc/homelabnext/memory-operators.yml"
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_SEALED = object()


class MemoryAdminError(Exception):
    """An operator memory action that was refused (who ran it, its configuration or its
    arguments); nothing was changed."""


class OperatorPrincipal:
    """The operator running ``hnx agent memory``: an OS ``user`` and ``uid`` from the operators
    file at ``source``.  Made only by :func:`invoking_operator`."""

    __slots__ = ("source", "uid", "user")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("OperatorPrincipal is sealed: it cannot be subclassed")

    def __init__(self, user: str, uid: int, source: str, token: object = None) -> None:
        if token is not _SEALED:
            raise TypeError(
                "an OperatorPrincipal is built only by the hnx agent memory command, from the "
                "invoking operating-system user"
            )
        object.__setattr__(self, "user", user)
        object.__setattr__(self, "uid", uid)
        object.__setattr__(self, "source", source)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("OperatorPrincipal is read-only")

    def __repr__(self) -> str:
        return f"OperatorPrincipal({self.user!r}, uid={self.uid}, from {self.source})"


def require_operator(by: Any) -> OperatorPrincipal:
    """``by`` when it is an :class:`OperatorPrincipal`; a ``VerifiedProfile``, a string or
    anything else raises ``TypeError``."""
    if type(by) is not OperatorPrincipal:
        raise TypeError(
            f"MemoryAdmin needs by=<OperatorPrincipal> (from hnx agent memory), not a "
            f"{type(by).__name__}: a profile never reaches it"
        )
    return by


@dataclass(frozen=True)
class OperatorConfig:
    """The operators file, read: who may run it, and the uids that never may."""

    operators: frozenset[str]
    refused: frozenset[int]
    source: str


def _read(path: Path) -> Any:
    import yaml

    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


def _peers(entries: Any, where: str, lookup: Callable[[str], int], problems: list[str]) -> set[int]:
    out: set[int] = set()
    if entries is None:
        return out
    if not isinstance(entries, list):
        problems.append(f"{where}: expected a list of {{user}} or {{uid}}")
        return out
    for n, e in enumerate(entries):
        if isinstance(e, Mapping) and isinstance(e.get("uid"), int) and e["uid"] >= 0:
            out.add(int(e["uid"]))
        elif (
            isinstance(e, Mapping) and isinstance(e.get("user"), str) and _USER.fullmatch(e["user"])
        ):
            try:
                out.add(lookup(e["user"]))
            except KeyError:
                problems.append(f"{where}[{n}]: no such user {e['user']!r}")
        else:
            problems.append(f"{where}[{n}]: expected {{user: <name>}} or {{uid: <n>}}")
    return out


def _unwritable(path: Path, refused: Iterable[int]) -> list[str]:
    """Why the runtime could write ``path`` (empty: it cannot): the file or a directory above it
    owned by a refused uid, or writable by a group or others (a sticky directory excepted)."""
    bad = set(refused)
    problems = []
    for p in [path, *path.parents]:
        st = p.stat()
        sticky = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX
        if st.st_uid in bad:
            problems.append(f"{p} is owned by uid {st.st_uid}, which the runtime or broker runs as")
        if st.st_mode & 0o022 and not sticky:
            problems.append(
                f"{p} is writable by its group or others (mode {stat.S_IMODE(st.st_mode):o})"
            )
    return problems


def load_operators(
    path: str | os.PathLike[str], *, lookup: Callable[[str], int] | None = None
) -> OperatorConfig:
    """The operators file at ``path`` (see the module doc), or :class:`MemoryAdminError`."""
    find = lookup or (lambda name: pwd.getpwnam(name).pw_uid)
    where = Path(path).resolve()
    try:
        doc = _read(where)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise MemoryAdminError(f"cannot read the operators file {path}: {exc}") from None
    except Exception as exc:  # a YAML error
        raise MemoryAdminError(f"cannot parse the operators file {path}: {exc}") from None
    if not isinstance(doc, Mapping):
        raise MemoryAdminError(f"{path}: expected a mapping with operators, agent_runtime, broker")
    unknown = sorted(set(doc) - {"operators", "agent_runtime", "broker", "broker_manifest"})
    problems = [f"{path}: unknown keys {unknown}"] if unknown else []
    ops = doc.get("operators")
    if not (
        isinstance(ops, list)
        and ops
        and all(isinstance(o, str) and _USER.fullmatch(o) for o in ops)
    ):
        problems.append(f"{path}: operators must be a non-empty list of user names")
        ops = []
    runtime = _peers(doc.get("agent_runtime"), "agent_runtime", find, problems)
    broker = _peers(doc.get("broker"), "broker", find, problems)
    manifest = doc.get("broker_manifest")
    if manifest is not None:
        if not isinstance(manifest, str):
            problems.append(f"{path}: broker_manifest must be a path")
        else:
            mpath = (where.parent / manifest).resolve()
            try:
                m = _read(mpath) or {}
            except Exception as exc:
                raise MemoryAdminError(f"cannot read the broker manifest {mpath}: {exc}") from None
            cm = m.get("codemode") or {} if isinstance(m, Mapping) else {}
            for name, entries in (
                ("callers", m.get("callers") if isinstance(m, Mapping) else None),
                ("codemode.runners", cm.get("runners")),
                ("codemode.sandboxes", cm.get("sandboxes")),
            ):
                runtime |= _peers(entries, f"{mpath}: {name}", find, problems)
    if not runtime:
        problems.append(
            f"{path}: no agent runtime user: list agent_runtime, or a broker_manifest with callers"
        )
    if not broker:
        problems.append(f"{path}: broker must list the user the broker runs as")
    refused = runtime | broker
    for o in ops:
        try:
            uid = find(o)
        except KeyError:
            continue  # an operator absent from this host simply never matches
        if uid in refused:
            problems.append(f"{path}: operator {o!r} is a user the agent runtime or broker runs as")
    if problems:
        raise MemoryAdminError(problems[0] if len(problems) == 1 else "; ".join(problems))
    unsafe = _unwritable(where, refused)
    if manifest is not None:
        unsafe += _unwritable((where.parent / manifest).resolve(), refused)
    if unsafe:
        raise MemoryAdminError(
            "the operators file must be reviewed configuration the runtime cannot write: "
            + "; ".join(unsafe)
        )
    return OperatorConfig(frozenset(ops), frozenset(refused), str(where))


def invoking_operator(config: OperatorConfig) -> OperatorPrincipal:
    """The :class:`OperatorPrincipal` of the user running this process, checked against
    ``config``; :class:`MemoryAdminError` for a refused uid or a user not in ``operators``.
    Only the ``hnx agent memory`` command calls it."""
    if type(config) is not OperatorConfig:
        raise TypeError("invoking_operator needs the OperatorConfig load_operators read")
    uid, euid = os.getuid(), os.geteuid()
    if uid in config.refused or euid in config.refused:
        raise MemoryAdminError(
            f"uid {uid if uid in config.refused else euid} is a user the agent runtime or the "
            "broker runs as: it may never run hnx agent memory"
        )
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise MemoryAdminError(f"uid {uid} has no user name") from None
    if user not in config.operators:
        raise MemoryAdminError(f"user {user!r} is not in the operators list of {config.source}")
    return OperatorPrincipal(user, uid, config.source, _SEALED)
