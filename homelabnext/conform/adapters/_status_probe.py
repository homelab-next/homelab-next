# SPDX-License-Identifier: Apache-2.0
"""The shared core of the read-only probes of the provisional slots that have no contract yet
(documents, enrichment): one GET against the resolved endpoint, no credential, the status code back."""

from __future__ import annotations

import urllib.error
import urllib.request

__all__ = ["StatusProbe"]


class StatusProbe:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _status(self, path: str) -> int:
        req = urllib.request.Request(self._base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                return int(r.status)
        except urllib.error.HTTPError as e:
            return int(e.code)

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None
