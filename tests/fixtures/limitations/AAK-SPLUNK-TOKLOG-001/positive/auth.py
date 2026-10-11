"""Session handling."""
import logging

logger = logging.getLogger(__name__)


def sign_in(access_token: str) -> None:
    logger.info("signed in with %s", access_token)
