import logging

from flask import Blueprint, request, make_response, jsonify, Response
from typing import List
from hubmap_commons.hm_auth import AuthHelper


privs_blueprint = Blueprint('privs', __name__)
logger = logging.getLogger(__name__)


@privs_blueprint.route('/privs/has-data-admin')
def privs_has_data_admin_privs():
    """
    The endpoint will return a status_code of 401 (as per the ingest-api-spec.yaml file)
    if the "User's token is not valid" (missing, or not logged in).
    For a valid logged in token it will return the json {'has_data_admin_privs': true/false}
    with a status_code of 200.
    """
    headers: dict = {
        "Content-Type": "application/json"
    }
    start_of_token: int = len('BEARER ')

    authorization: str = request.headers.get('authorization')
    if authorization is None or len(authorization) < start_of_token:
        return Response("Non-active login", 401)

    groups_token: str = authorization[start_of_token:]
    auth_helper_instance: AuthHelper = AuthHelper.instance()
    data_admin_privs: List[dict] = auth_helper_instance.has_data_admin_privs(groups_token)
    if isinstance(data_admin_privs, Response):
        return data_admin_privs
    return make_response(jsonify({"has_data_admin_privs": data_admin_privs}), 200, headers)
