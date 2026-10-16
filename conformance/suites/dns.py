# SPDX-License-Identifier: Apache-2.0
"""``dns`` (extended): authoritative zone semantics the registry's aliases depend on."""

from __future__ import annotations

from conformance.fakes.dns_zone import CaseSensitiveDnsZone, FakeDnsZone
from conformance.protocols.dns import CnameLoop, ConflictingRecord, NoSuchName
from homelabnext.conform.core import Mutant, Suite

from ._util import ip, raises, uniq

SUITE = Suite(
    "dns",
    "authoritative zone: records, case-insensitive names, NXDOMAIN vs NODATA, CNAME rules",
    "conformance.protocols.dns:DnsZone",
    tier="extended",
)


def _n(label="h"):
    return f"{uniq(label)}.svc.example.internal"


@SUITE.check("add-lookup-roundtrip", "an added A record is returned with its value and ttl")
def _(z):
    name = _n()
    z.add(name, "A", ip(10), 120)
    (rec,) = z.lookup(name, "A")
    assert (rec.value, rec.ttl) == (ip(10), 120), f"record {rec}"


@SUITE.check("names-are-case-insensitive", "Host.Example and host.example are the same name")
def _(z):
    name = _n("Mixed")
    z.add(name.upper(), "A", ip(11))
    assert [r.value for r in z.lookup(name.lower(), "A")] == [ip(11)]


@SUITE.check(
    "nxdomain-differs-from-nodata",
    "a missing name raises NoSuchName; a missing type is an empty list",
)
def _(z):
    name = _n()
    raises(lambda: z.lookup(name, "A"), "nxdomain", NoSuchName)
    z.add(name, "A", ip(12))
    assert z.lookup(name, "AAAA") == [], "NODATA must be an empty answer"


@SUITE.check("identical-add-is-idempotent", "adding the same record twice leaves one record")
def _(z):
    name = _n()
    z.add(name, "A", ip(13))
    z.add(name, "A", ip(13))
    assert len(z.lookup(name, "A")) == 1


@SUITE.check("multiple-values-sorted", "several A records come back sorted by value")
def _(z):
    name = _n()
    for addr in (ip(30), ip(20), ip(25)):
        z.add(name, "A", addr)
    assert [r.value for r in z.lookup(name, "A")] == [ip(20), ip(25), ip(30)]


@SUITE.check("bad-values-rejected", "a malformed address, unknown type or ttl <= 0 is refused")
def _(z):
    name = _n()
    raises(lambda: z.add(name, "A", "not-an-ip"), "bad A", ValueError)
    raises(lambda: z.add(name, "AAAA", ip(1)), "v4 in AAAA", ValueError)
    raises(lambda: z.add(name, "A", ip(1), 0), "ttl 0", ValueError)
    raises(lambda: z.add(name, "BOGUS", "x"), "unknown type", ValueError)


@SUITE.check("cname-is-followed", "asking for A on a CNAME name answers from the target")
def _(z):
    target, alias = _n("t"), _n("a")
    z.add(target, "A", ip(40))
    z.add(alias, "CNAME", target)
    assert [r.value for r in z.lookup(alias, "A")] == [ip(40)]


@SUITE.check("cname-loop-detected", "a CNAME cycle raises CnameLoop instead of hanging")
def _(z):
    a, b = _n("l"), _n("l")
    z.add(a, "CNAME", b)
    z.add(b, "CNAME", a)
    raises(lambda: z.lookup(a, "A"), "cname loop", CnameLoop)


@SUITE.check("cname-excludes-other-data", "a CNAME cannot share a name with other records")
def _(z):
    name = _n()
    z.add(name, "A", ip(50))
    raises(lambda: z.add(name, "CNAME", _n("t")), "cname next to A", ConflictingRecord)
    other = _n()
    z.add(other, "CNAME", _n("t"))
    raises(lambda: z.add(other, "A", ip(51)), "A next to cname", ConflictingRecord)


@SUITE.check(
    "remove-by-value-and-by-type", "remove deletes only what matches and reports the count"
)
def _(z):
    name = _n()
    z.add(name, "A", ip(60))
    z.add(name, "A", ip(61))
    z.add(name, "TXT", "scheme=https")
    assert z.remove(name, "A", ip(60)) == 1
    assert [r.value for r in z.lookup(name, "A")] == [ip(61)]
    assert z.remove(name, "A") == 1
    assert z.lookup(name, "TXT")[0].value == "scheme=https", "removing A removed the TXT"
    assert z.remove(name, "A") == 0, "removing nothing must report 0"


def make_fake():
    return FakeDnsZone()


MUTANTS = {
    "case-sensitive-names": Mutant(
        CaseSensitiveDnsZone, "names-are-case-insensitive", "names compare byte-for-byte"
    ),
}
