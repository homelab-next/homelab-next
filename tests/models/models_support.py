# SPDX-License-Identifier: Apache-2.0
import copy
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "tools"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from homelabnext.registry.model import build_registry


def make_registry():
    doc = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())
    base = doc["services"]["inference"]
    for name, port in (("inference-large", 8001), ("inference-small", 8002)):
        svc = copy.deepcopy(base)
        svc.update(capability=name, port=port)
        doc["services"][name] = svc
    return build_registry(doc)


def role_doc(large_model="example-27b", small_model="example-4b", large_backend="inference-large"):
    return {
        "version": 1,
        "roles": {
            "main-reasoner": {
                "tier": "large",
                "bindings": [{"backend": f"svc:{large_backend}", "model_id": large_model}],
                "fallback": "mdl:fast-classifier",
            },
            "fast-classifier": {
                "tier": "fast",
                "logprobs": True,
                "bindings": [{"backend": "svc:inference-small", "model_id": small_model}],
            },
            "embedder": {
                "kind": "embedding",
                "tier": "fast",
                "dimensions": 8,
                "bindings": [{"backend": "svc:inference-small", "model_id": "example-embed-8d"}],
            },
        },
    }
