# SPDX-License-Identifier: Apache-2.0
"""Recovery: what the restore drills prove (ADR-0042, ADR-0008 decision 2).

:mod:`.drills` reads the records the drill command (role ``restore_drill``) keeps and says, per
guest and per application, whether the last restore verified and how stale it is; it is the
observable behind checklist rows F-10 (restores are proven), F-14 (recovery targets met) and X-07
(export hooks exercised)."""
