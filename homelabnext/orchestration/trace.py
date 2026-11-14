# SPDX-License-Identifier: Apache-2.0
"""Wire names of a run's trace and run tokens (ADR-0047 decisions 2 and 5; ADR-0051 decision 13).

ADR-0047's step 3 adds the token format and its shared vectors here. Until then this module holds
the one name every party must agree on: the header a runner body sends the gateway's run token in.
The gateway verifies it and, like ``Authorization``, never writes its value to a log.
"""

from __future__ import annotations

__all__ = ["RUN_TOKEN_HEADER", "TRACE_HEADER"]

#: the header that carries the run's gateway token on every model call
RUN_TOKEN_HEADER = "X-HNX-Run-Token"
#: the W3C Trace Context header (ADR-0047 decision 1)
TRACE_HEADER = "traceparent"
