from flask import Blueprint, request, Response, current_app, jsonify
import logging
from rq import Retry
from pprint import pprint

from hubmap_commons.exceptions import HTTPException
from hubmap_sdk import EntitySdk
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from worker.utils import ResponseException

from app_utils.request_validation import require_json

from app_manager import groups_token_from_request_headers

bp = Blueprint('assayclassifier', __name__)

logger: logging.Logger = logging.getLogger(__name__)


def calculate_assay_info(metadata: dict) -> dict:
    print("metadata follows")
    pprint(metadata)
    print("metadata above")
    return {"hello": "world"}


@bp.route('/assaytype/<ds_uuid>', methods=['GET'])
def get_ds_assaytype(ds_uuid: str):
    try:
        entity_api_url = current_app.config['ENTITY_WEBSERVICE_URL']
        groups_token = groups_token_from_request_headers(request.headers)
        entity_api = EntitySdk(token=groups_token, service_url=entity_api_url)
        entity = entity_api.get_entity_by_id(ds_uuid)
        metadata = entity.ingest_metadata['metadata']
        return jsonify(calculate_assay_info(metadata))
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except (HTTPException, SDKException) as hte:
        return Response(f"Error while getting assay type for {ds_uuid}: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500)


@bp.route('/assaytype', methods=['POST'])
def get_assaytype_from_metadata():
    try:
        require_json(request)
        metadata = request.json
        return jsonify(calculate_assay_info(metadata))
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except (HTTPException, SDKException) as hte:
        return Response(f"Error while getting assay type from metadata: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while getting assay type from metadata: " + str(e), 500)


          
