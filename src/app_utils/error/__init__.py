from flask import abort


def unauthorized_error(err_msg):
    """
    Throws error for 401 Unauthorized with message
    Parameters
    ----------
    err_msg : str
        The custom error message to return to end users
    """
    abort(401, description=err_msg)

"""
Throws error for 403 Forbidden with message

Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def forbidden_error(err_msg):
    abort(403, description = err_msg)

def not_found_error(err_msg):
    """
    Throws error for 404 Not Found with message
    Parameters
    ----------
    err_msg : str
        The custom error message to return to end users
    """
    abort(404, description=err_msg)


def internal_server_error(err_msg):
    """
    Throws error for 500 Internal Server Error with message
    Parameters
    ----------
    err_msg : str
        The custom error message to return to end users
    """
    abort(500, description=err_msg)


def bad_request_error(err_msg):
    """
    Throws error for 400 Bad Reqeust with message
    Parameters
    ----------
    err_msg : str
        The custom error message to return to end users
    """
    abort(400, description=err_msg)
