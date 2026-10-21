# SPDX-License-Identifier: Apache-2.0
"""The ``projects`` contract on OpenProject (pinned: 17.9, API v3), stdlib HTTP.

``make(config=FILE)`` returns the library's own :class:`homelabnext.projects.ProjectStore` over
:class:`homelabnext.projects.openproject.OpenProjectBackend` -- the store ``hnx projects`` would
use against that instance -- configured by an ``openproject.yml`` (``docs/projects.md``; the API
token is read by its secret name, ``HNX_SECRET_OPENPROJECT_API_TOKEN``).  Every rule is the
store's, so the suite proves the mapping: work packages of type ``Project``/``Step``/``Task``,
the uid in the ``External key`` custom field, ``lockVersion`` as the version, relations as links.

``make(recorded_fake=True)`` runs the same adapter against the loopback stand-in for the API
recorded from OpenProject 17.9 (``conformance/fakes/openproject_api.py``, a source checkout only):
a fresh instance per subject, seeded with three Strategy work packages to link to, stopped when
the harness closes the subject.  ``conformance/targets/projects-openproject.yml`` binds it.

OpenProject specifics (limits of the product, not of this adapter):

* Relation-only changes do not move ``updatedAt``; the adapter's own link changes do (through
  the ``hnx state`` custom field), one made by hand in the UI shows at the next change.
* Times have second precision, so the change-feed cursor carries the versions already seen at
  its second.
* Each operation reads the work project's packages and relations once: right for a lab, not for
  a large instance.
"""

from __future__ import annotations

from typing import Any

from homelabnext.projects import ProjectStore

__all__ = ["make"]

#: the fake's Strategy records the suite links to (fictional UUIDv7s)
RECORDED_RECORDS = (
    "01941f29-7c00-7a3e-8b2c-000000000001",
    "01941f29-7c00-7a3e-8b2c-000000000002",
    "01941f29-7c00-7a3e-8b2c-000000000003",
)


def make(*, config: str | None = None, recorded_fake: bool = False, **_: Any) -> ProjectStore:
    """A ``projects`` subject on OpenProject: the instance ``config`` names, or (with
    ``recorded_fake``) a fresh loopback instance of the recorded API."""
    from homelabnext.projects.openproject import load_config, openproject_store

    if recorded_fake:
        return _on_recorded_fake()
    if not config:
        raise ValueError(
            "projects on OpenProject needs config: <openproject.yml> (or recorded_fake)"
        )
    return openproject_store(load_config(config))


def _on_recorded_fake() -> ProjectStore:
    try:
        from conformance.fakes.openproject_api import EXT_CF, TOKEN, FakeOpenProject
    except ImportError as exc:  # pragma: no cover - a wheel carries no conformance/
        raise ValueError("recorded_fake needs a source checkout (conformance/fakes)") from exc
    from homelabnext.projects.openproject import OpenProjectConfig, discover, openproject_store

    fake = FakeOpenProject().start()
    try:
        cfg = OpenProjectConfig(base_url=fake.url)
        client = cfg.client(env={"HNX_SECRET_OPENPROJECT_API_TOKEN": TOKEN})
        st = discover(client, cfg)
        for uid in RECORDED_RECORDS:
            links = {
                "type": {"href": f"/api/v3/types/{st.types['SO']}"},
                "status": {"href": f"/api/v3/statuses/{st.statuses['Active']}"},
            }
            body = {"subject": "record", EXT_CF: uid, "_links": links}
            client.post(f"/api/v3/projects/{st.strategy_project}/work_packages", body)
        store = openproject_store(cfg, client=client)
    except BaseException:
        fake.stop()
        raise
    store.backend.close = fake.stop  # type: ignore[attr-defined]  # the harness's teardown
    return store
