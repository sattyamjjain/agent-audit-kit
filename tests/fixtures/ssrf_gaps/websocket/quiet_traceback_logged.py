from __future__ import annotations

import logging
import traceback


def on_error() -> None:
    logging.error(traceback.format_exc())
