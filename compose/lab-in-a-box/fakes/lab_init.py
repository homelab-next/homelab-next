# SPDX-License-Identifier: Apache-2.0
"""One-shot initialiser for the lab-in-a-box stack (stdlib only, idempotent).

1. object store: assign the single-node layout, import the fixed fake access key, create the
   bucket and grant the key on it;
2. catalog: bootstrap the Iceberg REST catalog and create the warehouse that points at that
   bucket.

All endpoints and credentials come from the environment (see ``.env.example``); there are no
defaults, so a missing variable fails loudly.  Safe to run again: every step checks first.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"lab_init: environment variable {name} is required")
    return value


def call(
    method: str, url: str, body: Any = None, headers: dict[str, str] | None = None
) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw.decode(errors="replace")


def wait_for(url: str, headers: dict[str, str] | None = None, tries: int = 60) -> None:
    for _ in range(tries):
        try:
            status, _ = call("GET", url, headers=headers)
            if status < 500:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise SystemExit(f"lab_init: {url} never became reachable")


def init_object_store(admin: str, token: str, access: str, secret: str, bucket: str) -> None:
    auth = {"Authorization": f"Bearer {token}"}
    wait_for(f"{admin}/v1/status", auth)
    _, status = call("GET", f"{admin}/v1/status", headers=auth)
    node = status["node"]
    _, layout = call("GET", f"{admin}/v1/layout", headers=auth)
    if not layout.get("roles"):
        change = [{"id": node, "zone": "lab", "capacity": 1_000_000_000, "tags": []}]
        code, out = call("POST", f"{admin}/v1/layout", change, auth)
        if code >= 300:
            raise SystemExit(f"lab_init: layout stage failed: {code} {out}")
        code, out = call(
            "POST", f"{admin}/v1/layout/apply", {"version": layout["version"] + 1}, auth
        )
        if code >= 300:
            raise SystemExit(f"lab_init: layout apply failed: {code} {out}")
    code, _ = call("GET", f"{admin}/v1/key?id={access}", headers=auth)
    if code != 200:
        code, out = call(
            "POST",
            f"{admin}/v1/key/import",
            {"accessKeyId": access, "secretAccessKey": secret, "name": "lab-fake-key"},
            auth,
        )
        if code >= 300:
            raise SystemExit(f"lab_init: key import failed: {code} {out}")
    code, info = call("GET", f"{admin}/v1/bucket?globalAlias={bucket}", headers=auth)
    if code == 404:
        code, info = call("POST", f"{admin}/v1/bucket", {"globalAlias": bucket}, auth)
        if code >= 300:
            raise SystemExit(f"lab_init: bucket create failed: {code} {info}")
    grant = {
        "bucketId": info["id"],
        "accessKeyId": access,
        "permissions": {"read": True, "write": True, "owner": True},
    }
    code, out = call("POST", f"{admin}/v1/bucket/allow", grant, auth)
    if code >= 300:
        raise SystemExit(f"lab_init: bucket allow failed: {code} {out}")
    print("lab_init: object store ready", flush=True)


def init_catalog(base: str, warehouse: str, s3: dict[str, Any]) -> None:
    wait_for(f"{base}/health")
    _, info = call("GET", f"{base}/management/v1/info")
    if isinstance(info, dict) and not info.get("bootstrapped"):
        code, out = call("POST", f"{base}/management/v1/bootstrap", {"accept-terms-of-use": True})
        if code >= 300:
            raise SystemExit(f"lab_init: catalog bootstrap failed: {code} {out}")
    _, listing = call("GET", f"{base}/management/v1/warehouse")
    names = [w.get("name") for w in (listing or {}).get("warehouses", [])]
    if warehouse not in names:
        doc = {
            "warehouse-name": warehouse,
            "storage-profile": {
                "type": "s3",
                "bucket": s3["bucket"],
                "key-prefix": "warehouse",
                "region": s3["region"],
                "endpoint": s3["endpoint"],
                "path-style-access": True,
                "flavor": "s3-compat",
                "sts-enabled": False,
            },
            "storage-credential": {
                "type": "s3",
                "credential-type": "access-key",
                "aws-access-key-id": s3["access"],
                "aws-secret-access-key": s3["secret"],
            },
        }
        code, out = call("POST", f"{base}/management/v1/warehouse", doc)
        if code >= 300:
            raise SystemExit(f"lab_init: warehouse create failed: {code} {out}")
    print("lab_init: catalog ready", flush=True)


def main() -> int:
    access, secret = env("LAB_S3_ACCESS_KEY"), env("LAB_S3_SECRET_KEY")
    bucket = env("LAB_S3_BUCKET")
    init_object_store(
        env("LAB_OBJECT_STORE_ADMIN_URL"),
        env("LAB_OBJECT_STORE_ADMIN_TOKEN"),
        access,
        secret,
        bucket,
    )
    init_catalog(
        env("LAB_CATALOG_URL"),
        env("LAB_WAREHOUSE"),
        {
            "bucket": bucket,
            "region": env("LAB_S3_REGION"),
            "endpoint": env("LAB_S3_URL"),
            "access": access,
            "secret": secret,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
