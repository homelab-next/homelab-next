---
summary: 'Module manifest reference: registry equality, each selected module''s service rows checked against the lab registry as the site binds them.'
summary_of: outline:sha256:b36c3acd5b49e2a6
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: registry rows

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed); the selection that binds
> the rows is on [site selection](selection.md).

## Registry rows: checked, not generated

The lab's registry (`lab/services.yml`) stays hand-written: it is the one file every generator
(DNS, proxy, monitoring, firewall) reads, and the operator chose to **check it for equality**
rather than generate it from the selection. So `hnx modules check` (and `render`, which runs the
same check) requires every service row a selected module contributes (`contributes.services`) to
appear in the lab registry **identically, as the site binds it**
(`homelabnext.modules.registry_rows`):

- a provider's row is keyed by its slot and becomes one row per instance the site selects of that
  provider for that slot, named by the instance, with `version` the provider's `product.version`
  (a provider's row never repeats it); a feature's or core module's row keeps its name;
- `host` is the module's host role in the contributed row; in the registry it is where the site
  places that role: the guest's name for a host that references a guest
  (`hosts.<name>.guest: guest:<id>` gives `<id>`, the key the guest registry fragment uses), else
  the site host's own name;
- every other field must be equal, whole values compared (a mapping or list is one value). Each
  difference is its own problem under `registry`, naming the row, the field, the module (and
  instance) and both values, with `(absent)` for a field one side lacks:

  ```text
  registry: services.notify-eval.port: example-notify (instance notify-eval) contributes 80 (its row notify), the lab registry has 8080
  registry: services.notify-eval: example-notify (instance notify-eval) contributes this row (its row notify), but the lab registry has no such row (copy it as the site binds it)
  ```

- three fields are the lab's own facts about a row, which a generic module cannot know:
  `standing` (ADR-0039: eval, retiring or legacy, with `until` and `why`), `backup_job` and
  `scope` (which only narrows what agents file about the service). The registry may add them;
  they are compared only when the module's row sets them. `clients` is **not** one of them: extra
  zones widen who may reach the service, so a registry that adds them differs from the module.
  So the overlay's copy of a module's row is the bound row plus, at most, these three (an eval
  instance beside the primary: the module's fields exactly, and `standing`);
- two fields have a value that is the site's and a presence that is the module's:
  `public_hostname` and `edge_tls`. A module whose row is published at the edge (an IdP's
  sign-in pages) declares them with an example value (`sso.example.internal`, the CA's example
  secret name), which makes the row public in every check a module's rows meet (a public route
  needs auth and `grants.public_routes`); the lab registry must then carry each with **its own**
  value (its domain, its CA's secret name), which is not compared. A row whose module declares
  neither is compared as any other, so a site can never make a module's internal row public:

  ```text
  registry: services.idp.public_hostname: keycloak (instance idp) declares one (its value is the site's), the lab registry has (absent)
  ```

- a provider's row never sets `version` (the loader refuses one that does), so the product's
  version is the only one there is;
- a host role the site places on no host is a problem of its own (the registry's `host` cannot be
  judged); the row's other fields are still compared. A `version` is compared as text, so an
  unquoted YAML version equals its quoted form.

The comparison runs only against the lab's own registry (the overlay's `lab/services.yml`, or
`--services`); with the repository's example registry, which describes another lab, the report
notes that the rows were not compared. The comparison is one-directional: only the selected
modules' rows are judged, and a registry row that no selected module contributes is the lab's own
and is not compared. Values in a problem are
printed as JSON (control characters escaped) and cut at 120 characters.
