# SPDX-License-Identifier: Apache-2.0
"""The ``context`` suite against the service of modules/context, through its own HTTP routes.

The deployed service indexes only its configured sources, so the suite (which indexes and deletes
documents of its own) cannot run against the live instance.  This adapter proves the module's
code instead, in process, as the orchestration module's adapter proves its controller: the
suite's ``index`` and ``delete`` go to the service's store (every document labelled ``red``, the
contract's unlabelled default), and every ``query`` and ``get`` goes through the service's routes
(:class:`homelabnext.context_service.server.Routes`) as a JSON request of a caller whose ceiling is
``red``, and its JSON answer is read back into hits.  So what is proved is the store *and* the
HTTP mapping: scope, ordering, fidelity (content and digest survive the JSON), and the errors (400
is ``InvalidQuery``, 404 ``NotFound``).

``make(model_dir=None)``: the pinned model directory (or ``$HNX_CONTEXT_MODEL_DIR``); it needs the
``context-semantic`` extra.  ``store_factory`` is a test seam (the semantic adapter's own fakes).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Callable, Sequence
from typing import Any

from homelabnext import tlp as _tlp
from homelabnext.context import Document, Hit, IndexReport, InvalidQuery, NotFound, Query

from ._env import AdapterConfigError

__all__ = ["ServiceSubject", "make"]


class ServiceSubject:
    features = frozenset({"semantic"})

    def __init__(self, store_factory: Callable[[Any], Any], features: Sequence[str]) -> None:
        from homelabnext.context_service import config
        from homelabnext.context_service.server import Routes
        from homelabnext.context_service.service import ContextService

        self._dir = tempfile.TemporaryDirectory(prefix="hnx-context-conform-")
        reader = secrets.token_urlsafe(32)
        admin = secrets.token_urlsafe(32)
        cfg = config.parse(
            {
                "port": 8094,
                "model_dir": "/nonexistent",
                "data_dir": self._dir.name,
                "sources": [
                    {"name": "conform", "url": "https://git.example.internal/none.git",
                     "ref": "main", "kind": "doc", "tlp": "red", "paths": ["*"]}
                ],
                "callers": [{"name": "conform", "sha256": hashlib.sha256(reader.encode()).hexdigest(),
                             "ceiling": "red", "scopes": ["query"]}],
                "health": {"text": "x", "expect": "doc:conform/x", "ceiling": "red"},
            }
        )  # fmt: skip
        self._svc = ContextService(cfg, env={}, store_factory=store_factory)
        self._routes = Routes(self._svc, {"CONTEXT_ADMIN_TOKEN": admin})
        self._auth = f"Bearer {reader}"
        self.features = frozenset(features)

    def close(self) -> None:
        self._dir.cleanup()

    # -- the indexer side: the service's store ---------------------------------------------------
    def index(self, docs: Sequence[Document]) -> IndexReport:
        svc = self._svc
        with svc._lock:
            for d in docs:
                if isinstance(d, Document):
                    svc._labels[d.id] = _tlp.Label.RED
            report = svc._store.index(docs)
            svc._ids.update(report.added + report.replaced + report.unchanged)
            svc.indexed_once = True
            return report

    def delete(self, doc_id: str) -> None:
        with self._svc._lock:
            self._svc._store.delete(doc_id)
            self._svc._ids.discard(doc_id)

    # -- the reader side: the HTTP routes, JSON in and out ---------------------------------------
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        from homelabnext.context_service.server import ApiError

        try:
            status, doc = self._routes.handle(
                "POST", path, self._auth, json.loads(json.dumps(body))
            )
        except ApiError as exc:
            if exc.status == 404:
                raise NotFound(exc.message) from None
            if exc.status == 400:
                raise InvalidQuery(exc.message) from None
            raise
        assert status == 200
        return json.loads(json.dumps(doc))

    @staticmethod
    def _hit(h: dict[str, Any]) -> Hit:
        return Hit(h["id"], h["kind"], h["title"], h["path"], h["score"], h["snippet"],
                   h["content"], h["digest"])  # fmt: skip

    @staticmethod
    def _list(value: Any, what: str) -> Any:
        if isinstance(value, str | bytes):
            raise InvalidQuery(f"{what} must be a collection of strings")
        try:
            return sorted(value) if isinstance(value, set | frozenset) else list(value)
        except TypeError:
            raise InvalidQuery(f"{what} must be a collection of strings") from None

    def query(self, q: Query) -> list[Hit]:
        if not isinstance(q, Query):
            raise InvalidQuery("expected a Query")
        body = {
            "text": q.text,
            "allowed": self._list(q.allowed, "allowed"),
            "seeds": self._list(q.seeds, "seeds"),
            "kinds": None if q.kinds is None else self._list(q.kinds, "kinds"),
            "budget": q.budget,
            "include_inactive": q.include_inactive,
        }
        return [self._hit(h) for h in self._post("/v1/query", body)["hits"]]

    def get(self, doc_id: str, allowed: frozenset[str]) -> Hit:
        body = {"id": doc_id, "allowed": self._list(allowed, "allowed")}
        return self._hit(self._post("/v1/get", body)["hit"])


def make(
    model_dir: str | None = None,
    store_factory: Callable[[Any], Any] | None = None,
    features: Sequence[str] = ("semantic",),
) -> ServiceSubject:
    if store_factory is None:
        model_dir = model_dir or os.environ.get("HNX_CONTEXT_MODEL_DIR", "")
        if not model_dir:
            raise AdapterConfigError(
                "context: set model_dir or HNX_CONTEXT_MODEL_DIR to the pinned model directory"
            )
        from homelabnext.context_semantic import SemanticContextStore

        def store_factory(tlp_of):
            return SemanticContextStore(model_dir, ceiling="red", tlp_of=tlp_of)

    return ServiceSubject(store_factory, features)
