from flask import current_app
import requests
import logging
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper

logger: logging.Logger = logging.getLogger(__name__)


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


def get_entity_type_instanceof(type_a, type_b, auth_header=None) -> bool:
    if type_a is None:
        return False
    headers = None
    if auth_header is not None:
        headers = {'Authorization': auth_header, 'Accept': 'application/json', 'Content-Type': 'application/json'}

    base_url: str = commons_file_helper.removeTrailingSlashURL(
        current_app.config['ENTITY_WEBSERVICE_URL'])
    get_url: str = f"{base_url}/entities/type/{type_a}/instanceof/{type_b}"

    response = requests.get(get_url, headers=headers, verify=False)
    if response.status_code != 200:
        err_msg = f"Error while calling {get_url} status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        raise HTTPException(err_msg, response.status_code)

    resp_json: dict = response.json()
    return resp_json['instanceof']
