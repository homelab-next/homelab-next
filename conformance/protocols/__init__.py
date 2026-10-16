# SPDX-License-Identifier: Apache-2.0
"""Capability contracts as small ``typing.Protocol`` classes.

Where a library already exists in ``homelabnext`` (lake, notify, records, detections) the
protocol here re-exports or wraps it.  Where none exists yet, the protocol in this package *is*
the contract: an adapter for a real product implements it, raises the exception types defined
next to it, and is then proved by the matching suite in ``conformance/suites/``.

Conventions shared by every protocol:

* A method that cannot find a thing raises the protocol's ``NotFound``-style error; it never
  returns ``None`` for a missing thing and never creates it silently.
* Errors never contain secret values (inputs marked secret are redacted in messages).
* Time is explicit: implementations that expire things take a clock in their constructor and
  declare the optional feature ``clock-control`` (a ``tick(seconds)`` hook) so suites can test
  expiry without sleeping.  Real services leave the feature undeclared and the check is skipped.
* ``features`` (a set of strings on the subject) lists optional abilities; checks that need one
  declare ``requires=`` and are skipped, not failed, without it.
"""
