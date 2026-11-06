# SPDX-License-Identifier: Apache-2.0
"""Who may run ``MemoryAdmin`` (ADR-0037 decision 12, amended 2026-11-06): an
:class:`OperatorPrincipal`, built only by the ``hnx agent memory`` command from the invoking
operating-system user.

**The boundary is the uid and file ownership, not the Python type.**  An agent runtime that can
run arbitrary Python can build anything this module builds; what it cannot do is change its own
uid, or write files root owns.  So:

* The **operators file** (``/etc/homelabnext/memory-operators.yml``; ``--operators`` names another
  only when the effective uid is 0) is trusted only through root ownership: the file and every
  directory above it must be owned by uid 0 and writable by no group or other.  It is opened
  with ``O_NOFOLLOW`` and the same descriptor is ``fstat``-ed and parsed, so it cannot be swapped
  between the check and the read.  Its shape (YAML or JSON)::

      operators: [root]                # the OS users the command may run as (root under sudo)
      agent_runtime: [{user: hnx-agent}]  # users (or {uid: n}) the agent runtime runs as
      broker: [{user: hnx-broker}]     # users (or uids) the broker runs as
      broker_manifest: broker.yml      # optional, relative to this file
      deny_file: /var/lib/homelabnext-deny/memory-deny.json  # the one deny file, root's

* **Refused uids**, whatever ``operators`` says: ``agent_runtime``, ``broker``, the broker
  manifest's ``callers``, ``approval_relays``, ``operators`` (manifest 1.8 peers) and Code Mode
  ``runners`` and ``sandboxes``, and the owner of the memory state file (the runtime owns it,
  and the operators file cannot forge that).  **The runtime must not run as root**: a state file
  owned by uid 0 refuses every operator.
* The deployment runs ``hnx agent memory`` through ``sudo``: the principal's ``user`` is then
  ``root``, and ``by_sudo`` records ``SUDO_USER`` as advisory audit data (an environment
  variable, so it proves nothing).
* :func:`require_operator` re-checks the process's real and effective uids against the
  principal's and the refused set on every call, so a principal built some other way (or
  carried into another process) does not act.  ``_SEALED`` guards against accidents, not
  attacks.
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

from homelabnext.agent.memory import path_chain

__all__ = [
    "DEFAULT_OPERATORS",
    "MemoryAdminError",
    "OperatorConfig",
    "OperatorPrincipal",
    "OperatorsUnreadable",
    "check_root_owned",
    "invoking_operator",
    "load_operators",
    "require_operator",
]

#: where ``hnx agent memory`` reads the operators file
DEFAULT_OPERATORS = "/etc/homelabnext/memory-operators.yml"
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_SEALED = object()
#: the directory above which ownership is not checked (tests only; None checks up to /)
_TRUST_ABOVE: Path | None = None
#: the owners a trusted file may have: root (tests only add their own uid)
_ROOT_OWNERS: frozenset[int] = frozenset({0})


class MemoryAdminError(Exception):
    """An operator memory action that was refused (who ran it, its configuration or its
    arguments); nothing was changed."""


class OperatorsUnreadable(MemoryAdminError):
    """The operators file (or the broker manifest it names) cannot be read or parsed."""


class OperatorPrincipal:
    """The operator running ``hnx agent memory``: the OS ``user``, real ``uid`` and effective
    ``euid``, the ``refused`` uids it was checked against, the operators file (``source``) and
    the advisory ``by_sudo``.  Made only by :func:`invoking_operator`."""

    __slots__ = ("by_sudo", "euid", "refused", "source", "uid", "user")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("OperatorPrincipal is sealed: it cannot be subclassed")

    def __init__(
        self,
        user: str,
        uid: int,
        source: str,
        token: object = None,
        *,
        euid: int | None = None,
        refused: Iterable[int] = (),
        by_sudo: str | None = None,
    ) -> None:
        if token is not _SEALED:
            raise TypeError(
                "an OperatorPrincipal is built only by the hnx agent memory command, from the "
                "invoking operating-system user"
            )
        for name, value in (
            ("user", user),
            ("uid", uid),
            ("euid", uid if euid is None else euid),
            ("source", source),
            ("refused", frozenset(refused)),
            ("by_sudo", by_sudo),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("OperatorPrincipal is read-only")

    def __repr__(self) -> str:
        return f"OperatorPrincipal({self.user!r}, uid={self.uid}, from {self.source})"


def require_operator(by: Any) -> OperatorPrincipal:
    """``by`` when it is an :class:`OperatorPrincipal` of this very process: its uids are the
    process's real and effective uids now, and neither is refused.  A ``VerifiedProfile``, a
    string or anything else raises ``TypeError``; a principal that does not match the process
    raises :class:`MemoryAdminError`."""
    if type(by) is not OperatorPrincipal:
        raise TypeError(
            f"MemoryAdmin needs by=<OperatorPrincipal> (from hnx agent memory), not a "
            f"{type(by).__name__}: a profile never reaches it"
        )
    uid, euid = os.getuid(), os.geteuid()
    if (uid, euid) != (by.uid, by.euid) or uid in by.refused or euid in by.refused:
        raise MemoryAdminError(
            "this OperatorPrincipal is not this process's operator (its uids differ, or are "
            "refused): nothing was done"
        )
    return by


@dataclass(frozen=True)
class OperatorConfig:
    """The operators file, read: who may run it, and the uids that never may."""

    operators: frozenset[str]
    refused: frozenset[int]
    source: str
    #: the one deny file the runtime and the operator both use
    deny_file: str = ""

    def refusing(self, uids: Iterable[int]) -> OperatorConfig:
        """This configuration with ``uids`` refused too (the state file's owner)."""
        return OperatorConfig(
            self.operators, self.refused | frozenset(uids), self.source, self.deny_file
        )


def _peers(entries: Any, where: str, lookup: Callable[[str], int], problems: list[str]) -> set[int]:
    out: set[int] = set()
    if entries is None:
        return out
    if not isinstance(entries, list):
        problems.append(f"{where}: expected a list of {{user}} or {{uid}}")
        return out
    for n, e in enumerate(entries):
        uid = e.get("uid") if isinstance(e, Mapping) else None
        user = e.get("user") if isinstance(e, Mapping) else None
        if type(uid) is int and uid >= 0:  # never a bool: True is not uid 1
            out.add(uid)
        elif isinstance(user, str) and _USER.fullmatch(user):
            try:
                out.add(lookup(user))
            except KeyError:
                problems.append(f"{where}[{n}]: no such user {user!r}")
        else:
            problems.append(f"{where}[{n}]: expected {{user: <name>}} or {{uid: <n>}}")
    return out


def _chain(path: Path) -> list[Path]:
    """``path`` and the directories above it, up to ``/`` (or to :data:`_TRUST_ABOVE`): the
    walk the runtime's deny-file check uses too (:func:`homelabnext.agent.memory.path_chain`)."""
    return path_chain(path, stop=_TRUST_ABOVE)


def _mode_problems(p: Path, st: os.stat_result, owners: Iterable[int]) -> list[str]:
    problems = []
    if st.st_uid not in set(owners):
        problems.append(f"{p} is owned by uid {st.st_uid}, not root")
    if st.st_mode & 0o022:
        problems.append(
            f"{p} is writable by its group or others (mode {stat.S_IMODE(st.st_mode):o})"
        )
    return problems


def check_root_owned(
    path: str | os.PathLike[str], *, owners: Iterable[int] = (), depth: int | None = None
) -> list[str]:
    """Why ``path`` (which may not exist yet) and the directories above it are not trusted:
    each existing one must be owned by root (or, for the first ``depth`` names of the walk,
    ``path`` itself and its parent with ``depth=2``, by one of ``owners``; every name, without
    ``depth``), be no symbolic link and be writable by no group or other."""
    problems = []
    for n, p in enumerate(_chain(Path(os.path.abspath(path)))):
        allowed = set(owners) if depth is None or n < depth else set()
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{p} is a symbolic link")
            continue
        problems += _mode_problems(p, st, allowed | _ROOT_OWNERS)
    return problems


def _open_trusted(path: Path) -> tuple[Any, os.stat_result]:
    """Open ``path`` with ``O_NOFOLLOW`` and return its parsed document and the ``fstat`` of the
    descriptor that was read, so the checked file is the parsed one."""
    import yaml

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise OperatorsUnreadable(f"cannot open {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OperatorsUnreadable(f"{path} is not a regular file")
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            fd = -1
            text = fh.read()
    finally:
        if fd != -1:
            os.close(fd)
    try:
        doc = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise OperatorsUnreadable(f"cannot parse {path}: {exc}") from None
    return doc, st


def _trusted(path: Path, what: str) -> Any:
    doc, st = _open_trusted(path)
    problems = _mode_problems(path, st, _ROOT_OWNERS) + check_root_owned(path.parent)
    if problems:
        raise MemoryAdminError(
            f"the {what} must be reviewed configuration owned by root that the runtime cannot "
            "write: " + "; ".join(problems)
        )
    return doc


def load_operators(
    path: str | os.PathLike[str], *, lookup: Callable[[str], int] | None = None
) -> OperatorConfig:
    """The operators file at ``path`` (see the module doc), or :class:`MemoryAdminError`
    (:class:`OperatorsUnreadable` when it cannot be read or parsed)."""
    find = lookup or (lambda name: pwd.getpwnam(name).pw_uid)
    where = Path(os.path.abspath(path))
    doc = _trusted(where, "operators file")
    if not isinstance(doc, Mapping):
        raise MemoryAdminError(f"{path}: expected a mapping with operators, agent_runtime, broker")
    known = {"operators", "agent_runtime", "broker", "broker_manifest", "deny_file"}
    unknown = sorted(set(doc) - known)
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
            mpath = Path(os.path.abspath(where.parent / manifest))
            m = _trusted(mpath, "broker manifest") or {}
            m = m if isinstance(m, Mapping) else {}
            cm = m.get("codemode") if isinstance(m.get("codemode"), Mapping) else {}
            for name, entries in (
                ("callers", m.get("callers")),
                ("approval_relays", m.get("approval_relays")),
                ("operators", m.get("operators")),
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
    deny = doc.get("deny_file")
    if not isinstance(deny, str) or not os.path.isabs(deny):
        problems.append(f"{path}: deny_file must be the absolute path of the deny file")
        deny = ""
    if problems:
        raise MemoryAdminError("; ".join(problems))
    return OperatorConfig(frozenset(ops), frozenset(refused), str(where), deny)


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
            "broker runs as (or owns the memory state file): it may never run hnx agent memory"
        )
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise MemoryAdminError(f"uid {uid} has no user name") from None
    if user not in config.operators:
        raise MemoryAdminError(f"user {user!r} is not in the operators list of {config.source}")
    sudo = os.environ.get("SUDO_USER") or None
    return OperatorPrincipal(
        user, uid, config.source, _SEALED, euid=euid, refused=config.refused, by_sudo=sudo
    )
