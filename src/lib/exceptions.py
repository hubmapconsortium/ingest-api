import logging

from flask import Response

logger: logging.Logger = logging.getLogger(__name__)


class ResponseException(Exception):
    """Return a HTTP response from deep within the call stack"""

    def __init__(self, message: str, stat: int):
        self.message: str = message
        self.status: int = stat

    @property
    def response(self) -> Response:
        logger.error(f"message: {self.message}; status: {self.status}")
        return Response(self.message, self.status)
