# SPDX-License-Identifier: Apache-2.0
"""The serving plan: which engine serves which store entry for which role (docs/model-serving.md).

A serving spec (``schemas/platform/model_serving.schema.json``, YAML) joins the model store and
the role table.  It names, per ``svc:`` backend the role table binds, the engine that serves it
(``vllm`` or ``llama-server``), its port, its GPUs and its engine settings.  From the three
:func:`load_plan` derives, per backend, the one store entry it serves; :func:`render` writes the
``vllm_server`` role's input (``vllm_server/instances.yml``), and the LLM gateway generator reads
the same plan for its local backends (``serving:`` in a gateway spec), so neither the vLLM command
line nor the gateway's backend list is written by hand.

Rules (a violation raises :class:`ServingSpecError` listing every problem, nothing is written):

* every binding on a served backend resolves to exactly one store entry the backend's engine may
  serve (:func:`homelabnext.models.store.resolve_binding`), and a pinned digest names that entry;
* a vLLM backend serves one model (one ``--served-model-name``), so every binding on it names the
  same model id; its ``--max-model-len`` is the bound roles' ``max_context_tokens``, which they
  must declare and agree on, so the K-14 probe checks exactly what the engine was told;
* ports are unique, a GPU belongs to one backend, and ``tensor_parallel_size *
  pipeline_parallel_size`` is the number of GPUs a vLLM backend lists;
* engine arguments are an allowlist (:data:`ALLOWED_ARGS`): exact vLLM flag names with typed
  values (a whole number or fraction in range, a choice, a short parser name, or a boolean rendered
  as a bare flag when true).  No value may begin with ``-``, so a value cannot become a flag, and
  no flag outside the list passes, so neither an argparse abbreviation (``--hos``) nor a flag that
  loads code or files (``--config``, ``--middleware``, ``--hf-overrides``, ...) reaches the unit.
  The model, its name, context length, scheduling policy, address and parallelism always come
  from the plan (:data:`OWNED_FLAGS`).  The ``vllm_server`` role re-checks the rendered argv
  against the same list (its ``vars/main.yml`` is :func:`role_vars_text`, held equal by a test);
* every served backend is bound by some role (a backend nothing calls is dead config);
* ``exposure`` says where the engines listen, explicitly: ``zone`` (the host's zone address, so
  the gateway reaches each backend as ``<name>.svc.<domain>`` and the host firewall admits only
  it) or ``loopback`` (the host's loopback: reachable from the host alone, for bring-up).  It is rendered
  into the role's input, which holds ``vllm_server_listen_address`` to it, and the gateway
  generator refuses a ``loopback`` plan, whose backends it could never reach.

Every vLLM instance runs ``--scheduling-policy priority``: request priority belongs to the engine
(docs/llm-gateway.md), so the orchestrator's priorities reach it unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homelabnext.registry.models import RoleTable, RoleTableError

from . import store as store_mod
from .store import Entry, Store, StoreError

__all__ = [
    "ALLOWED_ARGS",
    "Arg",
    "Backend",
    "Plan",
    "ServingSpecError",
    "load_plan",
    "main",
    "plan_from_dict",
    "render",
    "role_vars_text",
]

SVC_RE = re.compile(r"^svc:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
FLAG_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
#: engines a serving spec may run a backend on.  Unsloth Studio may *load* store entries, but it
#: is the interactive GUI and trainer, not a backend the gateway routes agents to (ADR-0023).
SERVING_ENGINES = ("vllm", "llama-server")
#: vLLM flags the plan sets itself; ``args`` may not repeat or override them
OWNED_FLAGS = frozenset(
    {
        "model", "served-model-name", "max-model-len", "scheduling-policy", "host", "port",
        "tensor-parallel-size", "pipeline-parallel-size", "gpu-memory-utilization",
        "revision", "download-dir", "trust-remote-code", "api-key", "load-format",
    }
)  # fmt: skip


@dataclass(frozen=True)
class Arg:
    """How one allowlisted vLLM flag's value is checked and rendered.

    ``bool``: true renders the bare flag, false nothing; ``int``/``float``: a number in
    ``[lo, hi]``; ``enum``: one of ``choices``; ``name``: a short registered name (a parser, a
    quantization method), never a path or a module."""

    kind: str
    lo: float = 0
    hi: float = 0
    choices: tuple[str, ...] = ()

    @property
    def pattern(self) -> str | None:
        """The rendered value's regex (``None``: a bare flag), shared with the role."""
        if self.kind == "bool":
            return None
        if self.kind == "int":
            return r"^[0-9]{1,10}\Z"
        if self.kind == "float":
            return r"^[0-9]{1,6}(\.[0-9]{1,8})?\Z"
        if self.kind == "enum":
            return "^(" + "|".join(re.escape(c) for c in self.choices) + r")\Z"
        return r"^[a-z0-9][a-z0-9_.-]{0,31}\Z"


BOOL = Arg("bool")
NAME = Arg("name")
#: the vLLM flags ``args`` may set (exact names; ``vllm_server_version`` pins the release they are
#: checked against).  Left out on purpose: anything that names a file, a URL, a module or JSON
#: (``config``, ``chat-template``, ``tokenizer``, ``allowed-local-media-path``, ``middleware``,
#: ``tool-parser-plugin``, ``worker-extension-cls``, ``hf-overrides``, ``speculative-config``,
#: ``lora-modules``, ...), and everything in OWNED_FLAGS.
ALLOWED_ARGS: dict[str, Arg] = {
    # scheduling and batching
    "max-num-seqs": Arg("int", 1, 65536),
    "max-num-batched-tokens": Arg("int", 1, 1 << 24),
    "max-num-partial-prefills": Arg("int", 1, 64),
    "long-prefill-token-threshold": Arg("int", 0, 1 << 24),
    "enable-chunked-prefill": BOOL,
    "enable-prefix-caching": BOOL,
    "no-enable-prefix-caching": BOOL,
    "async-scheduling": BOOL,
    # memory and the KV cache
    "block-size": Arg("enum", choices=("8", "16", "32", "64", "128")),
    "kv-cache-dtype": Arg("enum", choices=("auto", "bfloat16", "fp8", "fp8_e4m3", "fp8_e5m2")),
    "swap-space": Arg("float", 0, 1024),
    "cpu-offload-gb": Arg("float", 0, 4096),
    "num-gpu-blocks-override": Arg("int", 1, 1 << 24),
    "calculate-kv-scales": BOOL,
    "enforce-eager": BOOL,
    "disable-custom-all-reduce": BOOL,
    "enable-expert-parallel": BOOL,
    "disable-sliding-window": BOOL,
    # numerics and the model's own settings
    "dtype": Arg("enum", choices=("auto", "half", "float16", "bfloat16", "float", "float32")),
    "quantization": NAME,
    "seed": Arg("int", 0, (1 << 32) - 1),
    "max-logprobs": Arg("int", 0, 100000),
    "generation-config": Arg("enum", choices=("auto", "vllm")),
    "tokenizer-mode": Arg("enum", choices=("auto", "slow", "mistral")),
    # the OpenAI-compatible frontend
    "enable-auto-tool-choice": BOOL,
    "tool-call-parser": NAME,
    "reasoning-parser": NAME,
    "response-role": NAME,
    "enable-prompt-tokens-details": BOOL,
    "enable-force-include-usage": BOOL,
    "return-tokens-as-token-ids": BOOL,
    "enable-request-id-headers": BOOL,
    "disable-fastapi-docs": BOOL,
    "disable-log-stats": BOOL,
    "enable-log-requests": BOOL,
    "disable-uvicorn-access-log": BOOL,
    "uvicorn-log-level": Arg(
        "enum", choices=("critical", "error", "warning", "info", "debug", "trace")
    ),
    "max-log-len": Arg("int", 0, 1 << 20),
}
BACKEND_KEYS = {
    "engine", "port", "gpus", "tensor_parallel_size", "pipeline_parallel_size",
    "gpu_memory_utilization", "args", "description",
}  # fmt: skip
OUT = "vllm_server/instances.yml"
#: where the engines listen (see the module docstring)
EXPOSURES = ("zone", "loopback")


class ServingSpecError(ValueError):
    """The serving spec, the store or the role table break a rule.  ``problems`` lists all."""

    def __init__(self, message: str, problems: Iterable[str] = ()):
        self.problems = list(problems)
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@dataclass(frozen=True)
class Backend:
    name: str  # svc name without the prefix
    engine: str
    port: int
    entry: Entry
    model_id: str
    roles: tuple[str, ...]
    max_model_len: int | None = None
    gpus: tuple[int, ...] = ()
    tensor_parallel_size: int = 1
    pipeline_parallel_size: int = 1
    gpu_memory_utilization: float = 0.9
    args: tuple[str, ...] = ()


@dataclass
class Plan:
    source: str
    store: Store
    table: RoleTable
    roles_path: Path
    backends: dict[str, Backend] = field(default_factory=dict)
    exposure: str = "zone"

    def engines(self) -> dict[str, str]:
        return {n: b.engine for n, b in self.backends.items()}

    def instance(self, b: Backend) -> dict[str, Any]:
        """The ``vllm_server`` role's input for one vLLM backend."""
        return {
            "name": b.name,
            "backend": f"svc:{b.name}",
            "roles": [f"mdl:{r}" for r in b.roles],
            "store_id": b.entry.id,
            "model_path": str(self.store.path_of(b.entry)),
            "served_model_name": b.model_id,
            "revision": b.entry.revision or b.entry.run,
            "digest": b.entry.digest,
            "max_model_len": b.max_model_len,
            "port": b.port,
            "gpus": list(b.gpus),
            "tensor_parallel_size": b.tensor_parallel_size,
            "pipeline_parallel_size": b.pipeline_parallel_size,
            "gpu_memory_utilization": b.gpu_memory_utilization,
            "args": list(b.args),
        }


def _whole(v: Any, lo: int, hi: int) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        return None
    return v


def _arg_value(rule: Arg, value: Any) -> str | None:
    """The rendered value of ``--flag``, or None when ``value`` is not one ``rule`` allows."""
    if rule.kind in ("int", "float"):
        ok = int if rule.kind == "int" else int | float
        if isinstance(value, bool) or not isinstance(value, ok) or not rule.lo <= value <= rule.hi:
            return None
        text = str(value)
    elif rule.kind == "enum":
        text = str(value) if isinstance(value, str | int) and not isinstance(value, bool) else ""
    else:
        text = value if isinstance(value, str) else ""
    pattern = rule.pattern
    return text if pattern and re.match(pattern, text) else None


def _args(where: str, raw: Any, problems: list[str]) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, Mapping):
        problems.append(f"{where}.args: a mapping of flag (without --) to value")
        return ()
    out: list[str] = []
    for flag, value in sorted(raw.items(), key=lambda kv: str(kv[0])):
        flag = str(flag)
        if not FLAG_RE.fullmatch(flag):
            problems.append(f"{where}.args: {flag!r} is not a flag name (lowercase, '-')")
            continue
        if flag in OWNED_FLAGS:
            problems.append(f"{where}.args: --{flag} is set by the plan, not by args")
            continue
        rule = ALLOWED_ARGS.get(flag)
        if rule is None:
            problems.append(
                f"{where}.args: --{flag} is not an allowed vLLM flag (exact names only, see "
                "homelabnext.models.serving.ALLOWED_ARGS; flags that load files, code or JSON "
                "are never allowed)"
            )
            continue
        if rule.kind == "bool":
            if not isinstance(value, bool):
                problems.append(f"{where}.args.{flag}: true (a bare flag) or false (omitted)")
            elif value:
                out.append(f"--{flag}")
            continue
        text = _arg_value(rule, value)
        if text is None:
            want = {
                "int": f"a whole number in [{int(rule.lo)}, {int(rule.hi)}]",
                "float": f"a number in [{rule.lo:g}, {rule.hi:g}]",
                "enum": f"one of {', '.join(rule.choices)}",
                "name": "a short name ([a-z0-9_.-], not starting with '-')",
            }[rule.kind]
            problems.append(f"{where}.args.{flag}: {value!r} is not {want}")
            continue
        out += [f"--{flag}", text]
    return tuple(out)


ROLE_VARS = "ansible/roles/vllm_server/vars/main.yml"


def role_vars_text() -> str:
    """``ansible/roles/vllm_server/vars/main.yml``: the allowlist as flag -> value regex (null: a
    bare flag), so the role re-checks a rendered argv against the same rules as the plan."""
    import yaml

    rules = {f: ALLOWED_ARGS[f].pattern for f in sorted(ALLOWED_ARGS)}
    return (
        "# SPDX-License-Identifier: Apache-2.0\n"
        "# Generated from homelabnext.models.serving.ALLOWED_ARGS (role_vars_text); a test holds\n"
        "# it equal. Fixed, not settings: the vLLM flags an instance's args may carry, each with\n"
        "# the regex its value must match (null: a bare flag, no value).\n"
        + yaml.safe_dump({"vllm_server_arg_rules": rules}, sort_keys=False, width=200)
    )


def plan_from_dict(doc: Any, *, base: Path, source: str = "<serving>") -> Plan:
    if not isinstance(doc, Mapping):
        raise ServingSpecError(f"{source}: a serving spec is a mapping")
    problems: list[str] = []
    for k in sorted(set(doc) - {"version", "store", "roles", "exposure", "backends"}):
        problems.append(f"unknown key {k!r}")
    exposure = doc.get("exposure")
    if exposure not in EXPOSURES:
        problems.append(
            f"exposure must be one of {EXPOSURES}: zone (the engines listen on the host's zone "
            "address, for the gateway) or loopback (on the loopback, for this host alone)"
        )
    for k in ("store", "roles"):
        if not isinstance(doc.get(k), str):
            raise ServingSpecError(f"{source}: {k!r} (a path) is required")
    roles_path = (base / doc["roles"]).resolve()
    try:
        store = store_mod.load(base / doc["store"])
    except StoreError as exc:
        raise ServingSpecError(
            f"{source}: model store invalid", exc.problems or [str(exc)]
        ) from None
    except OSError as exc:
        raise ServingSpecError(f"{source}: cannot read the store: {exc}") from None
    try:
        table = RoleTable.load(roles_path)
    except RoleTableError as exc:
        raise ServingSpecError(f"{source}: role table invalid", exc.problems) from None
    except (OSError, ValueError) as exc:
        raise ServingSpecError(f"{source}: cannot read the role table: {exc}") from None
    plan = Plan(source, store, table, roles_path, exposure=str(exposure))

    raw = doc.get("backends")
    if not isinstance(raw, Mapping) or not raw:
        raise ServingSpecError(f"{source}: backends must name every served svc: backend")
    bound: dict[str, list[tuple[str, Any]]] = {}
    for rname, role in sorted(table.roles.items()):
        for b in role.bindings:
            bound.setdefault(b.backend, []).append((rname, b))
    ports: dict[int, str] = {}
    gpu_owner: dict[int, str] = {}
    for sid, b in raw.items():
        m = SVC_RE.match(str(sid))
        where = f"backends.{sid}"
        if not m or not isinstance(b, Mapping):
            problems.append(f"{where}: the key is a svc: id and the value a mapping")
            continue
        name = m.group(1)
        before = len(problems)
        for k in sorted(set(b) - BACKEND_KEYS):
            problems.append(f"{where}: unknown key {k!r}")
        engine = b.get("engine")
        if engine not in SERVING_ENGINES:
            problems.append(
                f"{where}: engine must be one of {SERVING_ENGINES} (Unsloth Studio is the GUI "
                "and trainer, not a gateway backend)"
            )
            continue
        port = _whole(b.get("port"), 1024, 65535)
        if port is None:
            problems.append(f"{where}: port must be 1024-65535 (the unit holds no capabilities)")
        elif ports.setdefault(port, name) != name:
            problems.append(f"{where}: port {port} is also svc:{ports[port]}'s")
        gpus_raw = b.get("gpus", [])
        gpus = (
            [g for g in gpus_raw if _whole(g, 0, 63) is not None]
            if isinstance(gpus_raw, list)
            else []
        )
        if (
            not isinstance(gpus_raw, list)
            or len(gpus) != len(gpus_raw)
            or len(set(gpus)) != len(gpus)
        ):
            problems.append(f"{where}: gpus is a list of distinct GPU indexes (0-63)")
        for g in gpus:
            if gpu_owner.setdefault(g, name) != name:
                problems.append(f"{where}: GPU {g} is also svc:{gpu_owner[g]}'s")
        tp = _whole(b.get("tensor_parallel_size", 1), 1, 64)
        pp = _whole(b.get("pipeline_parallel_size", 1), 1, 64)
        util = b.get("gpu_memory_utilization", 0.9)
        if engine == "vllm":
            if tp is None or pp is None:
                problems.append(f"{where}: tensor/pipeline_parallel_size are whole numbers >= 1")
            elif not gpus or tp * pp != len(gpus):
                problems.append(
                    f"{where}: tensor_parallel_size x pipeline_parallel_size ({tp} x {pp}) must "
                    f"equal the number of gpus ({len(gpus)})"
                )
            if isinstance(util, bool) or not isinstance(util, int | float) or not 0 < util <= 1:
                problems.append(f"{where}: gpu_memory_utilization is a fraction in (0, 1]")
        elif any(k in b for k in ("tensor_parallel_size", "pipeline_parallel_size",
                                  "gpu_memory_utilization")):  # fmt: skip
            problems.append(f"{where}: parallelism and memory settings are vLLM-only")
        args = _args(where, b.get("args"), problems)
        if engine != "vllm" and args:
            problems.append(f"{where}: args are vLLM flags; llama-server is not rendered here")
        uses = bound.get(name, [])
        if not uses:
            problems.append(f"{where}: no role binds svc:{name}, so it would serve nothing")
            continue
        if len(problems) > before:
            continue
        model_ids = sorted({bd.model_id for _, bd in uses})
        if engine == "vllm" and len(model_ids) > 1:
            problems.append(
                f"{where}: one vLLM process serves one model, but roles bind {model_ids}; give "
                "each model its own backend"
            )
            continue
        entries: dict[str, Entry] = {}
        for rname, bd in uses:
            entry, why = store_mod.resolve_binding(
                store, bd.model_id, engine=str(engine), digest=bd.digest
            )
            if entry is None:
                problems.append(f"mdl:{rname} -> svc:{name} {bd.model_id}: {why}")
            else:
                entries[entry.id] = entry
        if len(entries) > 1:
            problems.append(f"{where}: its bindings pin different store entries {sorted(entries)}")
        if len(entries) != 1:
            continue
        (entry,) = entries.values()
        role_names = tuple(sorted({r for r, _ in uses}))
        ctx = sorted(
            {
                table.roles[r].max_context_tokens
                for r in role_names
                if table.roles[r].max_context_tokens is not None
            }
        )
        if engine == "vllm" and len(ctx) != 1:
            problems.append(
                f"{where}: the roles it serves ({', '.join('mdl:' + r for r in role_names)}) must "
                f"declare one max_context_tokens for --max-model-len (found {ctx or 'none'}); "
                "the K-14 probe checks the loaded context against it"
            )
            continue
        plan.backends[name] = Backend(
            name=name,
            engine=str(engine),
            port=int(port or 0),
            entry=entry,
            model_id=model_ids[0],
            roles=role_names,
            max_model_len=ctx[0] if ctx else None,
            gpus=tuple(gpus),
            tensor_parallel_size=int(tp or 1),
            pipeline_parallel_size=int(pp or 1),
            gpu_memory_utilization=float(util),
            args=args,
        )
    if problems:
        raise ServingSpecError(f"{source}: invalid serving spec", problems)
    return plan


def load_plan(path: str | Path) -> Plan:
    import yaml

    from homelabnext._yaml import UniqueKeyLoader

    path = Path(path)
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    return plan_from_dict(doc, base=path.parent, source=path.as_posix())


HEADER = (
    "# generated by hnx model_serving from {spec} - do not edit; sha256:{digest}\n"
    "# SPDX-License-Identifier: Apache-2.0\n"
)


def render(plan: Plan) -> dict[str, str]:
    """``{relative path: text}``: the ``vllm_server`` role's instances, deterministic."""
    import yaml

    instances = [plan.instance(b) for _, b in sorted(plan.backends.items()) if b.engine == "vllm"]
    doc = {"vllm_server_exposure": plan.exposure, "vllm_server_instances": instances}
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16]
    return {OUT: HEADER.format(spec=Path(plan.source).name, digest=digest) + body}


def main(argv: Iterable[str] | None = None) -> int:
    from homelabnext.generators.core import check_tree, write_tree

    ap = argparse.ArgumentParser(prog="hnx models serving", description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=("render", "check"))
    ap.add_argument("spec")
    ap.add_argument("out_dir")
    args = ap.parse_args(list(argv) if argv is not None else None)
    try:
        files = render(load_plan(args.spec))
    except ServingSpecError as exc:
        print(f"serving: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"serving: cannot read {args.spec}: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out_dir)
    if args.action == "check":
        problems = check_tree(out, files)
        for p in problems:
            print(f"serving: {p}", file=sys.stderr)
        if not problems:
            print(f"serving: {len(files)} file(s) match {args.spec}")
        return 1 if problems else 0
    res = write_tree(out, files)
    print(f"serving: wrote {len(res.written)}, unchanged {len(res.unchanged)} in {out}")
    return 0
