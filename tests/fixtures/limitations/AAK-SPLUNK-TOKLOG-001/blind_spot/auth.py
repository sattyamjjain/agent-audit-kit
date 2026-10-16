"""Session handling."""
import logging

_logger = logging.getLogger(__name__)


def sign_in(access_token: str) -> None:
    value = access_token
    _logger.info("signed in with %s", value)
