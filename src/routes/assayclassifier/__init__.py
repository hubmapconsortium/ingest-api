from flask import Blueprint, request, Response, current_app, jsonify
import logging
from sys import stdout
from typing import Callable
import json
import urllib.request
import urllib.error

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

from .source_is_human import source_is_human

bp = Blueprint("assayclassifier", __name__)

logger: logging.Logger = logging.getLogger(__name__)

pre_rule_chain = None
body_rule_chain = None
post_rule_chain = None


def initialize_rule_chains():
    global pre_rule_chain, body_rule_chain, post_rule_chain
    rule_src_uri = current_app.config["RULE_CHAIN_URI"]
    try:
        rule_json = urllib.request.urlopen(rule_src_uri)
    except json.decoder.JSONDecodeError as excp:
        raise RuleSyntaxException(excp) from excp
    rule_chain_dict = RuleLoader(rule_json).load()
    pre_rule_chain = rule_chain_dict["pre"]
    body_rule_chain = rule_chain_dict["body"]
    post_rule_chain = rule_chain_dict["post"]


def calculate_assay_info(metadata: dict,
                         source_is_human: bool,
                         lookup_ubkg: Callable[[str], dict]
                         ) -> dict:
    if any(elt is None
           for elt in [pre_rule_chain, body_rule_chain, post_rule_chain]):
        initialize_rule_chains()
    for key, value in metadata.items():
        if type(value) is str:
            if value.isdigit():
                metadata[key] = int(value)
    try:
        pre_values = pre_rule_chain.apply(metadata)
        body_values = body_rule_chain.apply(metadata, ctx=pre_values)
        assert "ubkg_code" in body_values, ("Rule matched but lacked ubkg_code:"
                                            f" {body_values}")
        ubkg_values = lookup_ubkg(body_values.get("ubkg_code", "NO_CODE")).get("value", {})
        rslt = post_rule_chain.apply(
            {},
            ctx={
                "source_is_human": source_is_human,
                "values": body_values,
                "ubkg_values": ubkg_values,
                "pre_values": pre_values,
                # "DEBUG": True
            }
        )
        return rslt
    except NoMatchException:
        return {}


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


def get_entity(ds_uuid: str) -> object:
    """
    Given a uuid and the (implicit) request, return the entity-sdk
    entity.
    """
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

    return entity


def get_entity_json(ds_uuid: str) -> dict:
    """
    Return the JSON associated with the entity associated with the given uuid
    """
    return get_entity(ds_uuid).metadata


def build_entity_metadata(entity) -> dict:
    metadata = {}
    dag_prov_list = []
    if hasattr(entity, "ingest_metadata"):
        # This if block should catch primary datasets because primary datasets should
        # have their metadata ingested as part of the reorganization.
        if hasattr(entity, "metadata") and not isinstance(entity.metadata, list):
            metadata = entity.metadata
        else:
            # If there is no ingest-metadata, then it must be a derived dataset
            metadata["data_types"] = calculate_data_types(entity)

        dag_prov_list = [elt['origin'] + ':' + elt['name']
                         for elt in entity.ingest_metadata.get('dag_provenance_list',
                                                               [])
                         if 'origin' in elt and 'name' in elt
                         ]

        # In the case of Publications, we must also set the data_types.
        # The primary publication will always have metadata,
        # so we have to do the association here.
        if entity.entity_type == "Publication":
            metadata["data_types"] = calculate_data_types(entity)

    # If there is no ingest_metadata, then it must be a derived dataset
    else:
        metadata["data_types"] = calculate_data_types(entity)

    metadata["entity_type"] = entity.entity_type
    if metadata["entity_type"].upper() in ["DONOR", "SAMPLE"]:
        raise ValueError(f"Entity is a {metadata['entity_type']}")
    logger.info(f"Entity type is {metadata['entity_type']}")
    metadata["dag_provenance_list"] = dag_prov_list
    metadata["creation_action"] = entity.creation_action

    return metadata


def get_data_from_ubkg(ubkg_code: str) -> dict:
    query = urllib.parse.urlencode({"application_context": current_app.config['APPLICATION_CONTEXT']})
    ubkg_api_url = f"{current_app.config['UBKG_INTEGRATION_ENDPOINT']}assayclasses/{ubkg_code}?{query}"
    req = urllib.request.Request(ubkg_api_url)
    try:
        with urllib.request.urlopen(req) as response:
            response_data = response.read().decode("utf-8")
    except urllib.error.URLError as excp:
        print(f"Error getting extra info from UBKG {excp}")
        return {}

    return json.loads(response_data)


@bp.route("/assaytype/<ds_uuid>", methods=["GET"])
def get_ds_assaytype(ds_uuid: str):
    try:
        entity = get_entity(ds_uuid)
        metadata = build_entity_metadata(entity)
        is_human = source_is_human(
            [ds_uuid],
            lambda some_uuid: (entity.metadata if some_uuid == ds_uuid
                               else get_entity_json(some_uuid))
        )
        rules_json = calculate_assay_info(metadata,
                                          is_human,
                                          get_data_from_ubkg
                                          )
        return jsonify(rules_json)
    except ValueError as excp:
        logger.error(excp, exc_info=True)
        return Response("Bad parameter: {excp}", 400)
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


@bp.route("/assaytype/metadata/<ds_uuid>", methods=["GET"])
def get_ds_rule_metadata(ds_uuid: str):
    try:
        entity = get_entity(ds_uuid)
        metadata = build_entity_metadata(entity)
        return jsonify(metadata)
    except ValueError as excp:
        logger.error(excp, exc_info=True)
        return Response("Bad parameter: {excp}", 400)
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
        if parent_sample_ids := metadata.get("parent_sample_id"):
            is_human = source_is_human(parent_sample_ids.split(","),
                                       get_entity_json)
        else:
            is_human = True  # default to human for safety
        rules_json = calculate_assay_info(metadata, is_human, get_data_from_ubkg)
        return jsonify(rules_json)
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
