from flask import abort, current_app
import requests
import logging
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper

logger: logging.Logger = logging.getLogger(__name__)


def __get_dict_prop(dic, prop_name):
    if prop_name not in dic:
        return None
    val = dic[prop_name]
    if isinstance(val, str) and val.strip() == '':
        return None
    return val


def __get_entity(entity_uuid, auth_header=None):
    if auth_header is None:
        headers = None
    else:
        headers = {'Authorization': auth_header, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    get_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) +\
              'entities/' + entity_uuid

    response = requests.get(get_url, headers=headers, verify=False)
    if response.status_code != 200:
        err_msg = f"Error while calling {get_url} status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        raise HTTPException(err_msg, response.status_code)

    return response.json()


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
