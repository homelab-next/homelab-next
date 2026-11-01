# SPDX-License-Identifier: Apache-2.0
"""The server catalog (``homelabnext.mcp.servers``) and the repository MCP server's tools
(``homelabnext.mcp.catalog``) no longer share the class names ``Catalog`` and ``CatalogError``:
``except CatalogError`` caught one or the other depending on the import."""

import pytest

from homelabnext.mcp import catalog, servers


def test_the_server_catalog_has_its_own_names():
    assert servers.ServerCatalog.__name__ == "ServerCatalog"
    assert servers.ServerCatalogError.__name__ == "ServerCatalogError"
    assert servers.ServerCatalog is not catalog.Catalog
    assert not issubclass(servers.ServerCatalogError, catalog.CatalogError)
    assert not issubclass(catalog.CatalogError, servers.ServerCatalogError)
    with pytest.raises(servers.ServerCatalogError, match="no MCP catalog directory"):
        servers.load("/nonexistent/mcp-catalog.invalid")


def test_the_old_names_still_resolve_for_one_release_and_warn():
    with pytest.warns(DeprecationWarning, match="renamed ServerCatalog"):
        assert servers.Catalog is servers.ServerCatalog
    with pytest.warns(DeprecationWarning, match="renamed ServerCatalogError"):
        assert servers.CatalogError is servers.ServerCatalogError
    with pytest.raises(AttributeError):
        servers.NoSuchName  # noqa: B018
