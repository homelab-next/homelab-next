#!/opt/strata/terminal/python/bin/python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: strata-healthcheck
#   kind: tool
#   purpose: Report whether the Strata server in the container answers /health with its model loaded.
#   owner: platform
#   trigger: [role:strata]
#   inputs: the PORT environment variable (default 8080)
#   outputs: the reason on stderr when it is not healthy
#   installs_to: /opt/strata/healthcheck.py
#   exit:
#     "0": the server answered 200 with the model loaded
#     "1": it did not answer, or the model is not loaded yet
# Container health: GET /health on the server's own port; healthy only when it answers 200 with the model loaded.
# While the model loads (minutes: ~76 GB over the card's link) the container is "starting", not "unhealthy".
import json
import os
import sys
import urllib.request

url = f"http://localhost:{os.environ.get('PORT', '8080')}/health"
try:
    with urllib.request.urlopen(url, timeout=4) as r:
        body = json.load(r)
        sys.exit(
            0
            if r.status == 200 and body.get("status") == "ok" and body.get("loaded") is True
            else 1
        )
except Exception as e:
    print(f"not healthy: {e}", file=sys.stderr)
    sys.exit(1)
