# SPDX-License-Identifier: Apache-2.0
"""The names of the IdP realm format the ``idp_realm`` generator renders (ADR-0034 decision 2).

The realm document is the reference IdP product's own import format, so these two names are that
product's: the registry ``impl`` a row needs for its realm to be rendered, and the realm
component that holds the declarative user profile (where the reserved usernames are refused).
They live here, and only here, so the product-name lint has one place to allow them; every
other module takes them from here."""

from __future__ import annotations

#: the product whose realm format the generator renders (registry ``impl``; ADR-0039 decision 2)
REALM_PRODUCT = "keycloak"
#: the realm component (``components`` key) of the declarative user profile
USER_PROFILE_PROVIDER = "org.keycloak.userprofile.UserProfileProvider"
