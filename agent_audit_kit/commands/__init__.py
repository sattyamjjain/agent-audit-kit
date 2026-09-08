"""Per-command implementations, split out of ``cli.py``.

``cli.py`` grew to 1,618 lines with 23 top-level commands, of which the ``scan``
command and its private ``_run_scan`` helper were 440 — a quarter of the file for
one command (issue #701). This package holds command bodies; ``cli.py`` keeps the
group, the remaining commands, and the registration.

Import direction is one-way: ``cli`` imports from ``commands``, never the
reverse. That is why the shared constants and config helpers live in
``_common`` rather than in ``cli`` — a command module reaching back into ``cli``
for ``EXIT_ERROR`` would make the group unimportable. ``cli`` re-exports every
name it moved here, so ``from agent_audit_kit.cli import SEVERITY_MAP`` keeps
working.
"""

from __future__ import annotations
