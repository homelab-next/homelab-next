# SPDX-License-Identifier: Apache-2.0
"""A notification channel's TLP ceiling (ADR-0033 decision 13: notification channels, and logs
and error text that reach one, are egress points).

:class:`CeilingSender` wraps a sender and applies the shared egress check
(:func:`homelabnext.tlp_egress.egress_check`) to every message before it leaves: the message's
label is the strictest of the label it claims (``Message.tlp``; none is ``red``) and every TLP
marker in its title, body, tags, link, topic and email target.  A notification is not stored, so
it has no recorded label.  A message above the channel's ceiling is not sent as written: a fixed
notice goes in its place, at the same level and priority, to the channel's default topic and no
extra email target, carrying only the fixed ``recovered`` tag when the message was a recovery and
saying only that a notification was withheld and at which label.  So the page still arrives and
nothing the message's producer wrote leaves.  The notifier's state is unchanged by the swap: it
still holds the problem as sent, and the recovery, labelled at least as strictly as the problem
(:meth:`Notifier._recover`), goes through the same check.

The default ceiling is ``red``: a channel only the lab's operators read admits everything, and
behaviour is unchanged until a channel is given a lower one.  No producer in this repository
labels its messages yet, so on a channel below ``red`` every one of their pages arrives as the
notice: safe, and only useful once producers claim labels.
"""

from __future__ import annotations

import logging
from dataclasses import replace

from homelabnext import tlp
from homelabnext.tlp_egress import NO_RECORD, egress_check

from .core import Message, Sender

__all__ = ["WITHHELD_TITLE", "CeilingSender", "ceiling_arg", "ceiling_from_flag"]

WITHHELD_TITLE = "Notification withheld (TLP)"

log = logging.getLogger("homelabnext.notify")


class CeilingSender:
    """Send through ``inner`` what ``ceiling`` (a parsed label) admits; a notice in place of the
    rest.  ``withheld`` counts the messages replaced."""

    def __init__(self, inner: Sender, ceiling: tlp.Label) -> None:
        if type(ceiling) is not tlp.Label:
            raise TypeError(f"ceiling must be a Label, not {type(ceiling).__name__}")
        self.inner = inner
        self.ceiling = ceiling
        self.withheld = 0

    def __repr__(self) -> str:
        return f"CeilingSender({self.inner!r}, ceiling={self.ceiling})"

    def send(self, message: Message) -> None:
        body = [
            message.title,
            message.body,
            list(message.tags),
            message.click or "",
            message.topic or "",
            message.email or "",
        ]
        decision = egress_check(self.ceiling, message.tlp, recorded=NO_RECORD, body=body)
        if decision.allowed:
            self.inner.send(message)
            return
        self.withheld += 1
        log.warning(
            "notification withheld: labelled %s, above the channel's %s ceiling",
            decision.label,
            self.ceiling,
        )
        notice = replace(
            message,
            title=WITHHELD_TITLE,
            body=(
                f"A {message.level} notification labelled {decision.label} is above this "
                f"channel's {self.ceiling} ceiling and was not sent; read it where it is held."
            ),
            tags=("recovered",) if "recovered" in message.tags else (),
            click=None,
            topic=None,
            email=None,
            tlp=str(self.ceiling),
        )
        self.inner.send(notice)


def ceiling_from_flag(value: object) -> tlp.Label:
    """``--notify-ceiling`` parsed as a declaration: ``None`` (the flag not given) is ``red``, a
    parsed label is itself, and anything but a label is refused (``ValueError``), never read as
    ``red``."""
    if value is None:
        return tlp.Label.RED
    if type(value) is tlp.Label:
        return value
    try:
        return tlp.parse(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--notify-ceiling: {exc}") from None


def ceiling_arg(value: str) -> tlp.Label:
    """:func:`ceiling_from_flag` as an argparse ``type``: a bad label is a usage error."""
    import argparse

    try:
        return ceiling_from_flag(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None
