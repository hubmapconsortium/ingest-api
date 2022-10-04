import logging
from app_utils.error import bad_request_error

logger: logging.Logger = logging.getLogger(__name__)


def require_json(request):
    """
    Always expect a json body from user request

    request : Flask request object
        The Flask request passed from the API endpoint
    """
    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required")

