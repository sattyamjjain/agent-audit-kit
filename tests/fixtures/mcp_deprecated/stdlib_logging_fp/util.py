"""FP guard: ordinary stdlib logging in a non-MCP module.

Python's stdlib logger level control is not the deprecated MCP capability, and
with no MCP context in the file this must NOT fire AAK-MCP-DEPRECATED-003.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def do_work(sampling_rate: float) -> None:
    # 'sampling_rate' is a plain variable name, not an MCP capability.
    logger.debug("working at rate %s", sampling_rate)
