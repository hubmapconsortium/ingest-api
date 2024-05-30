from flask import abort, Response
from enum import IntEnum
from typing import Union
from werkzeug.exceptions import NotFound, Forbidden, BadRequest, NotAcceptable, Unauthorized, InternalServerError


class StatusCodes(IntEnum):
    OK = 200
    OK_PARTIAL = 207
    BAD_REQUEST = BadRequest.code
    NOT_FOUND = NotFound.code
    UNACCEPTABLE = NotAcceptable.code
    SERVER_ERR = InternalServerError.code
    FORBIDDEN = Forbidden.code
    UNAUTHORIZED = Unauthorized.code


def abort_bad_req(desc):
    abort(StatusCodes.BAD_REQUEST, description=desc)


def abort_internal_err(desc):
    abort(StatusCodes.SERVER_ERR, description=desc)


def abort_not_found(desc):
    abort(StatusCodes.NOT_FOUND, description=desc)


def abort_forbidden(desc):
    abort(StatusCodes.FORBIDDEN, description=desc)


def abort_unauthorized(desc):
    abort(StatusCodes.UNAUTHORIZED, description=desc)


def rest_forbidden(desc, dict_only: bool = False) -> Union[dict, Response]:
    response = rest_response(StatusCodes.FORBIDDEN, StatusMsgs.FORBIDDEN, desc, True)
    return _rest_return(response, dict_only)


def rest_unauthorized(desc, dict_only: bool = False) -> Union[dict, Response]:
    response = rest_response(StatusCodes.UNAUTHORIZED, StatusMsgs.UNAUTHORIZED, desc, True)
    return _rest_return(response, dict_only)
