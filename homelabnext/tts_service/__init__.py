# SPDX-License-Identifier: Apache-2.0
"""The cloned-voice speech service of ``modules/tts`` (its README says what it is and why).

Standard library only at import time: the speech engine (torch and the voice model) is imported
by :mod:`homelabnext.tts_service.engine` only when a job needs it, so the HTTP contract, the
gates and the load/unload policy are tested without either.  The module's image copies this
package as ``tts_service`` and runs ``python -m tts_service serve``.
"""
