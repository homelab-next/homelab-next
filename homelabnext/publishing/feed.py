# SPDX-License-Identifier: Apache-2.0
"""The podcast feed: a deterministic ``feed.xml`` from the episodes in the bucket.

A port of the old pipeline's feed builder, byte for byte in structure.  The one hard rule it keeps:
once an episode's key is in the feed it never changes (a podcast app caches the enclosure URL),
so a key is ``<period>_<date>`` and nothing renames it.
"""

from __future__ import annotations

import re
import xml.sax.saxutils as xml_escape
from dataclasses import dataclass
from datetime import UTC, datetime

ARTWORK_KEY = "artwork.png"
_PERIOD = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}\Z")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
_GUID = re.compile(r"<guid[^>]*>([^<]*)</guid>")


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class FeedConfig:
    public_base_url: str
    title: str
    description: str
    author: str
    owner_email: str
    category: str = "Technology"

    def __post_init__(self) -> None:
        if not self.public_base_url.startswith("https://") or self.public_base_url.endswith("/"):
            raise FeedError("public_base_url is an https URL without a trailing slash")
        for f in ("title", "description", "author", "owner_email"):
            if not getattr(self, f):
                raise FeedError(f"feed {f} is empty")


@dataclass(frozen=True)
class Episode:
    stem: str  # <period>_<date>
    date: str
    title: str
    description: str
    size: int  # the mp3's byte length


def stem_of(meta: object) -> tuple[str, str]:
    """``(stem, date)`` of an episode's metadata; the parts are checked so a key cannot escape."""
    if not isinstance(meta, dict):
        raise FeedError("episode metadata is not an object")
    period, date = meta.get("period"), meta.get("date")
    if not isinstance(period, str) or not _PERIOD.match(period):
        raise FeedError("episode period is not a lowercase slug")
    if not isinstance(date, str) or not _DATE.match(date):
        raise FeedError("episode date is not YYYY-MM-DD")
    datetime.strptime(date, "%Y-%m-%d")
    return f"{period}_{date}", date


def _rfc2822(date_str: str) -> str:
    dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def _esc(s: object) -> str:
    return xml_escape.escape(str(s or ""))


def build_feed(episodes: list[Episode], cfg: FeedConfig) -> str:
    # stem order first, then newest date first: the stable sort keeps stem order within a date,
    # which is the order a bucket listing gives (the old builder's order)
    ordered = sorted(sorted(episodes, key=lambda e: e.stem), key=lambda e: e.date, reverse=True)
    base = cfg.public_base_url
    artwork = f"{base}/{ARTWORK_KEY}"
    items = []
    for ep in ordered:
        url = f"{base}/episodes/{ep.stem}.mp3"
        items.append(
            f"""    <item>
      <title>{_esc(ep.title or ep.stem)}</title>
      <description>{_esc(ep.description)}</description>
      <link>{_esc(base)}</link>
      <enclosure url="{_esc(url)}" length="{ep.size}" type="audio/mpeg"/>
      <guid isPermaLink="false">{_esc(ep.stem)}</guid>
      <pubDate>{_rfc2822(ep.date)}</pubDate>
      <itunes:explicit>false</itunes:explicit>
    </item>"""
        )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"
     xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>{_esc(cfg.title)}</title>
    <link>{_esc(base)}</link>
    <language>en-us</language>
    <itunes:author>{_esc(cfg.author)}</itunes:author>
    <description>{_esc(cfg.description)}</description>
    <itunes:image href="{_esc(artwork)}"/>
    <image>
      <url>{_esc(artwork)}</url>
      <title>{_esc(cfg.title)}</title>
      <link>{_esc(base)}</link>
    </image>
    <itunes:category text="{_esc(cfg.category)}"/>
    <itunes:explicit>false</itunes:explicit>
    <itunes:owner>
      <itunes:name>{_esc(cfg.author)}</itunes:name>
      <itunes:email>{_esc(cfg.owner_email)}</itunes:email>
    </itunes:owner>
{chr(10).join(items)}
  </channel>
</rss>
"""


def guids(feed_xml: str) -> set[str]:
    """The episode guids a feed already carries (what must never disappear from it)."""
    return {xml_escape.unescape(g) for g in _GUID.findall(feed_xml)}
