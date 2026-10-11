"""Session handling."""
import logging

_logger = logging.getLogger(__name__)
LOG = _logger


def sign_in(access_token: str) -> None:
    _logger.info("signed in with %s", access_token)


class Session:
    def __init__(self) -> None:
        self._logger = _logger

    def refresh(self, access_token: str) -> None:
        self._logger.info("refreshed with %s", access_token)


def audit(access_token: str) -> None:
    LOG.info("audited with %s", access_token)
