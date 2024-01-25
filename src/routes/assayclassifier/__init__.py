from flask import Blueprint, request, Response, current_app, jsonify
import logging
from rq import Retry
from sys import stdout
import json
import urllib.request

from hubmap_commons.exceptions import HTTPException
from hubmap_sdk import EntitySdk
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from werkzeug.exceptions import HTTPException as WerkzeugException
from worker.utils import ResponseException

from app_utils.request_validation import require_json

from app_manager import groups_token_from_request_headers

from .rule_chain import (
    RuleLoader,
    RuleChain,
    NoMatchException,
    RuleSyntaxException,
    RuleLogicException,
)

bp = Blueprint("assayclassifier", __name__)

logger: logging.Logger = logging.getLogger(__name__)


rule_chain = None


def initialize_rule_chain():
    global rule_chain
    rule_src_uri = current_app.config["RULE_CHAIN_URI"]
    try:
        json_rules = urllib.request.urlopen(rule_src_uri)
    except json.decoder.JSONDecodeError as excp:
        raise RuleSyntaxException(excp) from excp
    rule_chain = RuleLoader(json_rules).load()
    print("RULE CHAIN FOLLOWS")
    rule_chain.dump(stdout)
    print("RULE CHAIN ABOVE")


def calculate_assay_info(metadata: dict) -> dict:
    if not rule_chain:
        initialize_rule_chain()
    for key, value in metadata.items():
        if type(value) is str:
            if value.isdigit():
                metadata[key] = int(value)
    rslt = rule_chain.apply(metadata)
    # TODO: check that rslt has the expected parts
    return rslt


def calculate_data_types(entity: dict) -> list[str]:
    data_types = [""]

    # Historically, we have used the data_types field. So check to make sure that
    # the data_types field is not empty and not a list of empty strings
    # If it has a value it must be an old derived dataset so use that to match the rules
    if hasattr(entity, "data_types") and entity.data_types \
            and set(entity.data_types) != {""}:
        data_types = entity.data_types
    # Moving forward (2024) we are no longer using data_types for derived datasets.
    # Rather, we are going to use the dataset_info attribute which stores similar information
    # to match the rules. dataset_info is delimited by "__", so we can grab the first
    # item when splitting by that delimiter and pass that through to the rules.
    elif hasattr(entity, "dataset_info") and entity.dataset_info:
        data_types = [entity.dataset_info.split("__")[0]]

    # Else case is covered by the initial data_types instantiation.
    return data_types


@bp.route("/assaytype/<ds_uuid>", methods=["GET"])
def get_ds_assaytype(ds_uuid: str):
    try:
        entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
        groups_token = (
            groups_token_from_request_headers(request.headers)
            if "AUTHORIZATION" in request.headers
            else None
        )
        entity_api = EntitySdk(token=groups_token, service_url=entity_api_url)
        try:
            entity = entity_api.get_entity_by_id(ds_uuid)
        except SDKException as excp:
            entity_api = EntitySdk(service_url=entity_api_url)
            entity = entity_api.get_entity_by_id(
                ds_uuid
            )  # may again raise SDKException

        metadata = {}
        if hasattr(entity, "ingest_metadata"):
            # This if block should catch primary datasets because primary datasets should
            # their metadata ingested as part of the reorganization.
            if "metadata" in entity.ingest_metadata:
                metadata = entity.ingest_metadata["metadata"]

            if 'dag_provenance_list' in entity.ingest_metadata:
                dag_prov_list = entity.ingest_metadata['dag_provenance_list']
            else:
                dag_prov_list = []

            dag_prov_list = [elt['origin'] + ':' + elt['name']
                             for elt in dag_prov_list
                             if 'origin' in elt and 'name' in elt
                             ]
            metadata.update({'dag_provenance_list': dag_prov_list})

            # In the case of Publications, we must also set the data_types.
            # The primary publication will always have metadata,
            # so we have to do the association here.
            if entity.entity_type == "Publication":
                metadata["data_types"] = calculate_data_types(entity)

        # If there is no metadata, then it must be a derived dataset
        else:
            metadata["data_types"] = calculate_data_types(entity)

        metadata["entity_type"] = entity.entity_type

        return jsonify(calculate_assay_info(metadata))
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except NoMatchException as excp:
        return {}
    except (RuleSyntaxException, RuleLogicException) as excp:
        return Response(f"Error applying classification rules: {excp}", 500)
    except WerkzeugException as excp:
        return excp
    except (HTTPException, SDKException) as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500
        )


@bp.route("/assaytype", methods=["POST"])
def get_assaytype_from_metadata():
    try:
        require_json(request)
        metadata = request.json
        return jsonify(calculate_assay_info(metadata))
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except NoMatchException as excp:
        return {}
    except (RuleSyntaxException, RuleLogicException) as excp:
        return Response(f"Error applying classification rules: {excp}", 500)
    except WerkzeugException as excp:
        return excp
    except (HTTPException, SDKException) as hte:
        return Response(
            f"Error while getting assay type from metadata: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while getting assay type from metadata: " + str(e), 500
        )


@bp.route("/reload-assaytypes", methods=["PUT"])
def reload_chain():
    try:
        initialize_rule_chain()
        return jsonify({})
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except (RuleSyntaxException, RuleLogicException) as excp:
        return Response(f"Error applying classification rules: {excp}", 500)
    except (HTTPException, SDKException) as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while reloading rule chain: " + str(e), 500)
