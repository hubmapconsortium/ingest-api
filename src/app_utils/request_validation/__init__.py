from flask import abort
import logging

logger: logging.Logger = logging.getLogger(__name__)


def require_json(request):
    """
    Always expect a json body from user request

    request : Flask request object
        The Flask request passed from the API endpoint
    """
    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required")


def bad_request_error(err_msg):
    """
    Throws error for 400 Bad Reqeust with message
    Parameters
    ----------
    err_msg : str
        The custom error message to return to end users
    """
    abort(400, description=err_msg)
