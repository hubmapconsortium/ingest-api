from flask import Blueprint, request, Response, current_app, jsonify
import logging
from sys import stdout
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

bp = Blueprint("assayclassifier", __name__)

logger: logging.Logger = logging.getLogger(__name__)


rule_chain = None

# Have to translate pre-UBKG keys to UBKG keys
# Format is:
# "Key before UBKG integration": "UBKG Key"
pre_integration_to_ubkg_translation = {
    'vitessce-hints': 'vitessce_hints',
    'dir-schema': 'dir_schema',
    'tbl-schema': 'tbl_schema',
    'contains-pii': 'contains_full_genetic_sequences',
    'dataset-type': 'dataset_type',
    'is-multi-assay': 'is_multiassay',
    'pipeline-shorthand': 'pipeline_shorthand',
    'must-contain': 'must_contain',
}

# These are the keys returned by the rule chain before UBKG integration.
# We will return the UBKG data in this format as well for MVP.
# This is to avoid too much churn on end-users.
# We set primary manually so ignore it.
pre_integration_keys = [
    'assaytype',
    'vitessce-hints',
    'dir-schema',
    'tbl-schema',
    'contains-pii',
    #'primary',
    'dataset-type',
    'description',
    'is-multi-assay',
    'pipeline-shorthand',
    'must-contain',
    "process_state"
]

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


def get_entity(ds_uuid: str) -> dict:
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


def build_entity_metadata(entity) -> dict:
    metadata = {}
    dag_prov_list = []
    if hasattr(entity, "ingest_metadata"):
        # This if block should catch primary datasets because primary datasets should
        # have their metadata ingested as part of the reorganization.
        if "metadata" in entity.ingest_metadata and not isinstance(entity.ingest_metadata["metadata"], list):
            metadata = entity.ingest_metadata["metadata"]
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

    # If there is no metadata, then it must be a derived dataset
    else:
        metadata["data_types"] = calculate_data_types(entity)

    metadata["entity_type"] = entity.entity_type
    if metadata["entity_type"].upper() in ["DONOR", "SAMPLE"]:
        raise ValueError(f"Entity is a {metadata['entity_type']}")
    logger.info(f"Entity type is {metadata['entity_type']}")
    metadata["dag_provenance_list"] = dag_prov_list
    metadata["creation_action"] = entity.creation_action

    return metadata


def apply_source_type_transformations(source_type: str, rule_value_set: dict) -> dict:
    # If we get more complicated transformations we should consider refactoring.
    # For now, this should suffice.
    if source_type.upper() == "MOUSE":
        rule_value_set["contains-pii"] = False

    return rule_value_set


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


def standardize_results(rule_chain_json: dict, ubkg_json: dict) -> dict:
    # Initialize this with conditional logic to set 'primary' true or false.
    ubkg_transformed_json = {
        "primary": ubkg_json.get("process_state") == "primary"
    }

    for pre_integration_key in pre_integration_keys:
        ubkg_key = pre_integration_to_ubkg_translation.get(pre_integration_key, pre_integration_key)
        ubkg_value = ubkg_json.get(ubkg_key)
        ubkg_transformed_json[pre_integration_key] = ubkg_value

    return rule_chain_json | ubkg_transformed_json


@bp.route("/assaytype/<ds_uuid>", methods=["GET"])
def get_ds_assaytype(ds_uuid: str):
    try:
        entity = get_entity(ds_uuid)
        metadata = build_entity_metadata(entity)
        rules_json = calculate_assay_info(metadata)

        if hasattr(entity, "sources") and isinstance(entity.sources, list):
            source_type = ""
            for source in entity.sources:
                if source_type := source.get("source_type"):
                    # If there is a single Human source_type, treat this as a Human case
                    if source_type.upper() == "HUMAN":
                        break
            apply_source_type_transformations(source_type, rules_json)

        ubkg_value_json = get_data_from_ubkg(rules_json.get("ubkg_code")).get("value", {})
        merged_json = standardize_results(rules_json, ubkg_value_json)
        merged_json["ubkg_json"] = ubkg_value_json
        return jsonify(merged_json)
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
        rules_json = calculate_assay_info(metadata)

        if parent_sample_ids := metadata.get("parent_sample_id"):
            source_type = ""
            parent_sample_ids = parent_sample_ids.split(",")
            for parent_sample_id in parent_sample_ids:
                parent_entity = get_entity(parent_sample_id)
                if hasattr(parent_entity, "source"):
                    if source_type := parent_entity.source.get("source_type"):
                        # If there is a single Human source_type, treat this as a Human case
                        if source_type.upper() == "HUMAN":
                            break
            apply_source_type_transformations(source_type, rules_json)

        ubkg_value_json = get_data_from_ubkg(rules_json.get("ubkg_code")).get("value", {})
        merged_json = standardize_results(rules_json, ubkg_value_json)
        merged_json["ubkg_json"] = ubkg_value_json
        return jsonify(merged_json)
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
