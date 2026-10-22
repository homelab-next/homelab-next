# SPDX-License-Identifier: Apache-2.0
"""The model store manifest: one copy of each model, pinned and hashed (docs/model-serving.md).

A store (``schemas/platform/model_store.schema.json``) lists every model the lab keeps on disk
under one root (``/srv/models`` by default), once per (source, revision, quant):

* ``format: hf``     - a Hugging Face safetensors snapshot, fetched into the hub cache layout
  ``hf/hub/models--<org>--<name>/snapshots/<revision>/`` (``HF_HOME=<root>/hf``);
* ``format: gguf``   - one single-file GGUF, under ``gguf/<org>/<name>/``;
* ``format: export`` - a fine-tune export (a merged LoRA, written by Unsloth Studio) under
  ``exports/<run>/``, with ``layout`` ``safetensors`` or ``gguf`` and the ``base`` entry it came
  from.

Every entry names the commit it was fetched at (a 40-hex revision, never a branch such as
``main``), every file's sha256 and size, its licence and the engines that may serve it.  Its
**digest** is ``sha256:`` of the ``sha256sum``-format listing of its files (``<hex>  <path>`` lines
in path order), so ``sha256sum`` reproduces it and a role binding's ``digest`` (G-11) names
exactly one set of bytes.

:func:`validate` refuses a malformed store (every problem, not the first); :func:`bindings_problems`
checks that every model-role binding resolves to a store entry an engine may serve;
:func:`check_disk` verifies the files on disk by sha256.  Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

__all__ = [
    "ENGINES",
    "Entry",
    "Store",
    "StoreError",
    "bindings_problems",
    "check_disk",
    "load",
    "resolve_binding",
]

ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[-.][a-z0-9]+)*$")
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
QUANT_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
LICENSE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
FILE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*$")
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
FORMATS = ("hf", "gguf", "export")
LAYOUTS = ("safetensors", "gguf")
#: engine -> the (format, layout) pairs it may serve.  vLLM serves safetensors only: its GGUF
#: path is an out-of-tree, single-file, "highly experimental" plugin, so production never runs
#: GGUF on it (ADR-0023).  llama-server serves GGUF only; Unsloth Studio loads either.
ENGINES: dict[str, frozenset[tuple[str, str]]] = {
    "vllm": frozenset({("hf", "safetensors"), ("export", "safetensors")}),
    "llama-server": frozenset({("gguf", "gguf"), ("export", "gguf")}),
    "unsloth-studio": frozenset(
        {("hf", "safetensors"), ("gguf", "gguf"), ("export", "safetensors"), ("export", "gguf")}
    ),
}
ENTRY_KEYS = {
    "description", "format", "layout", "quant", "source", "license", "served_model_name",
    "engines", "files", "base",
}  # fmt: skip


class StoreError(ValueError):
    """The store manifest is malformed.  ``problems`` lists every defect found."""

    def __init__(self, message: str, problems: Iterable[str] = ()):
        self.problems = list(problems)
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@dataclass(frozen=True)
class File:
    path: str  # relative to the entry's directory
    sha256: str
    size: int


@dataclass(frozen=True)
class Entry:
    id: str
    format: str  # hf | gguf | export
    layout: str  # safetensors | gguf
    quant: str
    license: str
    served_model_name: str
    engines: tuple[str, ...]
    files: tuple[File, ...]
    repo: str = ""  # hf, gguf: org/name on the hub
    revision: str = ""  # hf, gguf: the pinned commit
    run: str = ""  # export: the training run id
    base: str = ""  # export: the store entry it was trained from
    description: str = ""

    @property
    def source_key(self) -> tuple[str, str, str]:
        """What two entries must never share: (source, revision, quant)."""
        if self.format == "export":
            return (f"export:{self.run}", self.run, self.quant)
        return (self.repo, self.revision, self.quant)

    @property
    def directory(self) -> str:
        """The entry's directory, relative to the store root."""
        if self.format == "hf":
            org, name = self.repo.split("/", 1)
            return f"hf/hub/models--{org}--{name}/snapshots/{self.revision}"
        if self.format == "gguf":
            return f"gguf/{self.repo}"
        return f"exports/{self.run}"

    @property
    def listing(self) -> str:
        """The ``sha256sum`` listing of the entry's files (``<hex>  <path>`` lines, path order)."""
        return "".join(f"{f.sha256}  {f.path}\n" for f in sorted(self.files, key=lambda f: f.path))

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.listing.encode("utf-8")).hexdigest()

    @property
    def size(self) -> int:
        return sum(f.size for f in self.files)

    def servable_by(self, engine: str) -> bool:
        return engine in self.engines and (self.format, self.layout) in ENGINES.get(engine, ())


@dataclass
class Store:
    root: str
    entries: dict[str, Entry]
    version: int = 1

    @classmethod
    def from_dict(cls, doc: Any) -> Store:
        problems: list[str] = []
        if not isinstance(doc, Mapping) or not isinstance(doc.get("models"), Mapping):
            raise StoreError("a model store is a mapping with a 'models' mapping")
        for k in sorted(set(doc) - {"version", "root", "models"}):
            problems.append(f"unknown key {k!r}")
        root = doc.get("root", "/srv/models")
        if (
            not isinstance(root, str)
            or not re.fullmatch(r"/[A-Za-z0-9._/-]*", root)
            or (".." in PurePosixPath(root).parts)
        ):
            problems.append("root must be an absolute path of [A-Za-z0-9._/-]")
        entries: dict[str, Entry] = {}
        for eid, raw in doc["models"].items():
            entry = _entry(str(eid), raw, problems)
            if entry is not None:
                entries[entry.id] = entry
        if not doc["models"]:
            problems.append("models: the store lists no model")
        problems += _cross_problems(entries)
        if problems:
            raise StoreError("invalid model store", problems)
        return cls(str(root).rstrip("/") or "/", entries, int(doc.get("version", 1)))

    def path_of(self, entry: Entry) -> Path:
        return Path(self.root) / entry.directory

    def to_listing(self) -> list[dict[str, Any]]:
        """One row per entry: what ``hnx models store list`` prints."""
        return [
            {
                "id": e.id,
                "format": e.format,
                "quant": e.quant,
                "served_model_name": e.served_model_name,
                "engines": list(e.engines),
                "size": e.size,
                "digest": e.digest,
                "path": str(self.path_of(e)),
            }
            for _, e in sorted(self.entries.items())
        ]


def _entry(eid: str, raw: Any, problems: list[str]) -> Entry | None:
    where = f"models.{eid}"
    if not ID_RE.match(eid):
        problems.append(f"{where}: the id must be a lowercase slug ([a-z0-9], '-' or '.')")
        return None
    if not isinstance(raw, Mapping):
        problems.append(f"{where}: must be a mapping")
        return None
    before = len(problems)
    for k in sorted(set(raw) - ENTRY_KEYS):
        problems.append(f"{where}: unknown key {k!r}")
    fmt = raw.get("format")
    if fmt not in FORMATS:
        problems.append(f"{where}: format must be one of {FORMATS}")
        return None
    layout = {"hf": "safetensors", "gguf": "gguf"}.get(fmt) or raw.get("layout")
    if fmt == "export" and layout not in LAYOUTS:
        problems.append(f"{where}: an export needs layout in {LAYOUTS}")
    elif fmt != "export" and "layout" in raw and raw["layout"] != layout:
        problems.append(f"{where}: format {fmt} is layout {layout}; drop 'layout' or match it")
    quant = raw.get("quant")
    if not isinstance(quant, str) or not QUANT_RE.match(quant):
        problems.append(f"{where}: quant must be a short lowercase name (bf16, fp8, q4_k_m)")
    lic = raw.get("license")
    if not isinstance(lic, str) or not LICENSE_RE.match(lic):
        problems.append(f"{where}: license must be an SPDX id or a short licence name")
    served = raw.get("served_model_name")
    if not isinstance(served, str) or not MODEL_ID_RE.match(served):
        problems.append(f"{where}: served_model_name must be a model id ([A-Za-z0-9._:/-])")
    engines = raw.get("engines")
    if (
        not isinstance(engines, list)
        or not engines
        or any(e not in ENGINES for e in engines)
        or len(set(engines)) != len(engines)
    ):
        problems.append(f"{where}: engines must list some of {tuple(ENGINES)}, each once")
        engines = []
    repo = revision = run = base = ""
    src = raw.get("source")
    if fmt == "export":
        if (
            not isinstance(src, Mapping)
            or set(src) != {"run"}
            or not RUN_RE.match(str(src.get("run", "")))
        ):
            problems.append(f"{where}: an export's source is {{run: <training run id>}}")
        else:
            run = str(src["run"])
        base = str(raw.get("base", ""))
        if not ID_RE.match(base):
            problems.append(f"{where}: an export names the store entry it was trained from (base)")
    else:
        if "base" in raw:
            problems.append(f"{where}: only an export has a base")
        if not isinstance(src, Mapping) or set(src) != {"repo", "revision"}:
            problems.append(f"{where}: source is {{repo: <org>/<name>, revision: <commit>}}")
        else:
            repo, revision = str(src["repo"]), str(src["revision"])
            if not REPO_RE.match(repo) or ".." in repo:
                problems.append(f"{where}: source.repo must be <org>/<name>")
            if not REVISION_RE.match(revision):
                problems.append(
                    f"{where}: source.revision {revision!r} must be a full 40-hex commit hash, "
                    "never a branch or tag such as 'main' (a floating revision is a different "
                    "model tomorrow)"
                )
    files = _files(where, raw.get("files"), problems)
    if layout == "gguf":
        ggufs = [f for f in files if f.path.endswith(".gguf")]
        if len(ggufs) != 1:
            problems.append(
                f"{where}: a GGUF entry holds exactly one single-file .gguf (merge a split "
                "model with gguf-split --merge first)"
            )
    for e in engines:
        if layout and (fmt, layout) not in ENGINES[e]:
            problems.append(f"{where}: engine {e} cannot serve {fmt}/{layout}")
    if len(problems) > before:
        return None
    return Entry(
        id=eid,
        format=str(fmt),
        layout=str(layout),
        quant=str(quant),
        license=str(lic),
        served_model_name=str(served),
        engines=tuple(engines),
        files=tuple(files),
        repo=repo,
        revision=revision,
        run=run,
        base=base,
        description=str(raw.get("description", "")),
    )


def _files(where: str, raw: Any, problems: list[str]) -> list[File]:
    if not isinstance(raw, list) or not raw:
        problems.append(f"{where}: files must list every file, with sha256 and size")
        return []
    out: list[File] = []
    for i, f in enumerate(raw):
        w = f"{where}.files[{i}]"
        if not isinstance(f, Mapping) or set(f) != {"path", "sha256", "size"}:
            problems.append(f"{w}: needs exactly path, sha256 and size")
            continue
        path, sha, size = f["path"], f["sha256"], f["size"]
        if not isinstance(path, str) or not FILE_RE.match(path) or ".." in path.split("/"):
            problems.append(f"{w}: path must be relative, without '..' ([A-Za-z0-9._-] segments)")
            continue
        if not isinstance(sha, str) or not SHA_RE.match(sha):
            problems.append(f"{w}: sha256 must be 64 lowercase hex")
            continue
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            problems.append(f"{w}: size must be a whole number of bytes")
            continue
        out.append(File(path, sha, size))
    paths = [f.path for f in out]
    for dup in sorted({p for p in paths if paths.count(p) > 1}):
        problems.append(f"{where}: file {dup} is listed twice")
    return out


def _cross_problems(entries: Mapping[str, Entry]) -> list[str]:
    problems: list[str] = []
    seen: dict[tuple[str, str, str], str] = {}
    for eid, e in sorted(entries.items()):
        other = seen.setdefault(e.source_key, eid)
        if other != eid:
            src, rev, quant = e.source_key
            problems.append(
                f"models.{eid}: same source, revision and quant as {other} ({src}@{rev[:12]} "
                f"{quant}): the store keeps one copy of each"
            )
    owner: dict[str, str] = {}
    for eid, e in sorted(entries.items()):
        for f in e.files:
            p = f"{e.directory}/{f.path}"
            if owner.setdefault(p, eid) != eid:
                problems.append(f"models.{eid}: {p} is also a file of {owner[p]}")
    for eid, e in sorted(entries.items()):
        if e.format != "export":
            continue
        if e.base not in entries:
            problems.append(f"models.{eid}: base {e.base!r} is not a store entry")
        elif e.base == eid:
            problems.append(f"models.{eid}: an export cannot be its own base")
    return problems


def load(path: str | Path) -> Store:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except ValueError as exc:
        raise StoreError(f"{path}: not JSON ({exc})") from None
    return Store.from_dict(doc)


# ---------------------------------------------------------------- role bindings
def resolve_binding(
    store: Store, model_id: str, *, engine: str | None = None, digest: str | None = None
) -> tuple[Entry | None, str]:
    """The one store entry a binding serves, or ``(None, why)``.

    Candidates are the entries whose ``served_model_name`` is the binding's model id and (when the
    backend's engine is known) that the engine may serve; a binding's ``digest`` narrows them to
    the entry with that digest.  Exactly one must remain."""
    cands = [e for _, e in sorted(store.entries.items()) if e.served_model_name == model_id]
    if not cands:
        return None, f"no store entry serves model id {model_id!r}"
    if engine is not None:
        cands = [e for e in cands if e.servable_by(engine)]
        if not cands:
            return None, f"no store entry for {model_id!r} may be served by {engine}"
    else:
        cands = [e for e in cands if e.engines]
    if digest is not None:
        match = [e for e in cands if e.digest == digest]
        if not match:
            have = ", ".join(f"{e.id} {e.digest[:19]}" for e in cands)
            return None, f"pinned digest {digest[:19]}... matches no store entry ({have})"
        cands = match
    if len(cands) > 1:
        return None, (
            f"{model_id!r} is ambiguous: {', '.join(e.id for e in cands)} (pin the binding's "
            "digest, or give the entries distinct served_model_name values)"
        )
    return cands[0], ""


def bindings_problems(
    store: Store, table: Any, engines: Mapping[str, str] | None = None
) -> list[str]:
    """Every model-role binding resolves to a store entry an engine may serve.

    ``table`` is a :class:`homelabnext.registry.models.RoleTable`; ``engines`` maps a backend (svc
    name without the prefix) to its engine.  Without ``engines``, any listed engine will do.  A
    pinned binding's ``version``, when it looks like a commit, must be the entry's revision."""
    problems: list[str] = []
    for rname, role in sorted(table.roles.items()):
        for b in role.bindings:
            engine = (engines or {}).get(b.backend)
            if engines is not None and engine is None:
                continue  # not a store-served backend (a cloud provider, say)
            entry, why = resolve_binding(store, b.model_id, engine=engine, digest=b.digest)
            where = f"mdl:{rname} -> svc:{b.backend} {b.model_id}"
            if entry is None:
                problems.append(f"{where}: {why}")
                continue
            if (
                b.version
                and REVISION_RE.match(b.version)
                and entry.format != "export"
                and b.version != entry.revision
            ):
                problems.append(
                    f"{where}: pinned version {b.version[:12]} is not the store entry "
                    f"{entry.id}'s revision {entry.revision[:12]}"
                )
    return problems


# ---------------------------------------------------------------- on disk
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_disk(
    store: Store,
    root: str | Path | None = None,
    *,
    only: Iterable[str] | None = None,
    sizes_only: bool = False,
) -> list[str]:
    """Problems with the store's files under ``root`` (default: the manifest's root).

    Every listed file must exist (a hub-cache symlink is followed), have its size and, unless
    ``sizes_only``, its sha256.  A regular file in an entry's directory that no entry lists is
    reported too: an engine would load it, and nothing pins it (dot-directories, where the hub
    client keeps its download metadata, are skipped)."""
    base = Path(root if root is not None else store.root)
    wanted = set(only) if only is not None else set(store.entries)
    problems = [f"{u}: not a store entry" for u in sorted(wanted - set(store.entries))]
    listed: dict[str, set[str]] = {}
    for e in store.entries.values():
        listed.setdefault(e.directory, set()).update(f.path for f in e.files)
    for eid in sorted(wanted & set(store.entries)):
        e = store.entries[eid]
        d = base / e.directory
        for f in sorted(e.files, key=lambda f: f.path):
            p = d / f.path
            where = f"{eid}: {e.directory}/{f.path}"
            if not p.is_file():
                problems.append(f"{where}: missing")
                continue
            size = p.stat().st_size
            if size != f.size:
                problems.append(f"{where}: size {size}, manifest says {f.size}")
                continue
            if not sizes_only and _sha256(p) != f.sha256:
                problems.append(f"{where}: sha256 differs from the manifest")
        if d.is_dir():
            for p in sorted(d.rglob("*")):
                rel = p.relative_to(d).as_posix()
                if any(part.startswith(".") for part in rel.split("/")):
                    continue  # the hub client's own metadata (.cache/huggingface/), never loaded
                if (p.is_file() or p.is_symlink()) and rel not in listed[e.directory]:
                    problems.append(f"{eid}: {e.directory}/{rel}: not in the manifest")
    return problems
