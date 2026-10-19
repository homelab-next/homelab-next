# SPDX-License-Identifier: Apache-2.0
"""The what-changed event every deploy emits (``homelabnext.deploy.changed``, checklist F-15).

The release/deploy path calls :func:`deploy_changed_event` (or :func:`emit_deploy_changed`, which
also publishes it) with the component, the old and new versions and the changelog.  The
``changes`` list is read from the changelog section of the new version
(:func:`changes_from_changelog`, Keep a Changelog format), so the event can never claim a change
the changelog does not record, and a deploy whose version has no section is refused.

The event id derives from ``deploy_id``: a retried deploy step emits the same id, which the
publisher and the forwarder treat as a duplicate.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .envelope import build_event

EVENT_TYPE = "homelabnext.deploy.changed"
CHANGE_KINDS = ("added", "changed", "deprecated", "removed", "fixed", "security")
MAX_SUMMARY = 500
MAX_CHANGES = 200

_SECTION = re.compile(r"^## \[(?P<v>[^\]]+)\][^\n]*$", re.M)
_KIND = re.compile(r"^### (?P<k>[A-Za-z]+)\s*$")
_ITEM = re.compile(r"^[-*] (?P<t>.+)$")


class ChangelogError(ValueError):
    """The changelog has no usable section for the version."""


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_SUMMARY else text[: MAX_SUMMARY - 3].rstrip() + "..."


def changes_from_changelog(text: str, version: str) -> list[dict[str, str]]:
    """The ``{kind, summary}`` items of ``## [version]`` in a Keep a Changelog document.

    A list item continued on indented lines is joined into one summary.  Raises
    :class:`ChangelogError` when the section is missing or records no change.
    """
    heads = list(_SECTION.finditer(text))
    for i, m in enumerate(heads):
        if m.group("v") == version:
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            body = text[m.end() : end]
            break
    else:
        raise ChangelogError(f"no '## [{version}]' section in the changelog")
    out: list[dict[str, str]] = []
    kind: str | None = None
    for line in body.splitlines():
        k = _KIND.match(line)
        if k:
            kind = k.group("k").lower()
            if kind not in CHANGE_KINDS:
                raise ChangelogError(f"[{version}]: unknown change heading {k.group('k')!r}")
            continue
        it = _ITEM.match(line)
        if it and kind:
            out.append({"kind": kind, "summary": it.group("t")})
        elif line.startswith((" ", "\t")) and line.strip() and out:
            out[-1]["summary"] += " " + line.strip()
    if not out:
        raise ChangelogError(f"[{version}]: the section records no change")
    return [{"kind": c["kind"], "summary": _clip(c["summary"])} for c in out][:MAX_CHANGES]


def deploy_changed_event(
    *,
    component: str,
    to_version: str,
    changes: Iterable[Mapping[str, str]],
    source: str,
    deploy_id: str | None = None,
    from_version: str | None = None,
    environment: str | None = None,
    commit: str | None = None,
    changelog: str | None = None,
    time: str | None = None,
) -> dict[str, Any]:
    """Build (and validate) the ``homelabnext.deploy.changed`` envelope."""
    deploy_id = deploy_id or "-".join(
        p.replace(":", "-") for p in (component, to_version, environment or "") if p
    )
    data: dict[str, Any] = {
        "deploy_id": deploy_id,
        "component": component,
        "from_version": from_version,
        "to_version": to_version,
        "changes": [dict(c) for c in changes],
    }
    for k, v in (("environment", environment), ("commit", commit), ("changelog", changelog)):
        if v is not None:
            data[k] = v
    return build_event(
        EVENT_TYPE,
        source,
        data,
        dedupe_key=deploy_id,
        subject=component,
        severity="info",
        time=time,
    )


def emit_deploy_changed(publisher: Any, **kwargs: Any):
    """Build the event and hand it to a :class:`~homelabnext.events.Publisher`."""
    event = deploy_changed_event(**kwargs)
    return event, publisher.publish(event)
