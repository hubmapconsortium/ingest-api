import logging

from flask import Blueprint, request, make_response, jsonify, Response
from typing import List
from hubmap_commons.hm_auth import AuthHelper


privs_blueprint = Blueprint('privs', __name__)
logger = logging.getLogger(__name__)


@privs_blueprint.route('/privs/has-data-admin')
def privs_has_data_admin_privs():
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()

    data_admin_privs: List[dict] = auth_helper_instance.has_data_admin_privs(groups_token)
    if isinstance(data_admin_privs, Response):
        return data_admin_privs

    headers: dict = {
        "Content-Type": "application/json"
    }
    return make_response(jsonify({"has_data_admin_privs": data_admin_privs}), 200, headers)


def get_groups_token() -> str:
    return request.headers.get('authorization')[7:]
