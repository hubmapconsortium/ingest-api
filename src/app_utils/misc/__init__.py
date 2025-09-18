import logging

logger: logging.Logger = logging.getLogger(__name__)


def __get_dict_prop(dic, prop_name):
    if prop_name not in dic:
        return None
    val = dic[prop_name]
    if isinstance(val, str) and val.strip() == '':
        return None
    return val


class ResponseException(Exception):
    """Return a HTTP response from deep within the call stack"""
    def __init__(self, message: str, stat: int):
        self.message: str = message
        self.status: int = stat

    @property
    def response(self) -> Response:
        logger.error(f'message: {self.message}; status: {self.status}')
        return Response(self.message, self.status)

