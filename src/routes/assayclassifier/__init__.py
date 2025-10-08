from flask import Blueprint, request, Response, current_app, jsonify
import logging
from sys import stdout
from typing import Callable
import json
import urllib.request
import urllib.error

from hubmap_commons.exceptions import HTTPException
from werkzeug.exceptions import HTTPException as WerkzeugException
from app_utils.misc import ResponseException
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


def calculate_data_types(entity_json: dict) -> list[str]:
    data_types = [""]

    # Historically, we have used the data_types field. So check to make sure that
    # the data_types field is not empty and not a list of empty strings
    # If it has a value it must be an old derived dataset so use that to match the rules
    if ("data_types" in entity_json and entity_json["data_types"]
            and set(entity_json["data_types"]) != {""}):
        data_types = entity_json["data_types"]
    # Moving forward (2024) we are no longer using data_types for derived datasets.
    # Rather, we are going to use the dataset_info attribute which stores similar information
    # to match the rules. dataset_info is delimited by "__", so we can grab the first
    # item when splitting by that delimiter and pass that through to the rules.
    elif "dataset_info" in entity_json and entity_json["dataset_info"]:
        data_types = [entity_json["dataset_info"].split("__")[0]]

    # Else case is covered by the initial data_types instantiation.
    return data_types


def wrapped_get_json(url: str) -> dict:
    """
    Do a GET on the given URL with appropriate auth tokens, returning
    the json content of the response.  Setting use_auth=False suppresses
    the attempt to add an Authorization header
    """
    req = urllib.request.Request(url)
    if "AUTHORIZATION" in request.headers:
        groups_token = groups_token_from_request_headers(request.headers)
        req.add_header("Authorization", f"Bearer {groups_token}")

    try:
        return json.loads(urllib.request.urlopen(req).read())
    except urllib.error.HTTPError:
        raise


def get_entity_json(ds_uuid: str) -> dict:
    """
    Return the JSON associated with the entity associated with the given uuid
    """
    entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
    if not entity_api_url.endswith('/'):
        entity_api_url = entity_api_url + '/'
    entity_json = wrapped_get_json(entity_api_url + 'entities/' + ds_uuid + '?exclude=direct_ancestors.files')
    return entity_json


def build_entity_metadata(entity_json: dict) -> dict:
    metadata = {}
    dag_prov_list = []
    if "ingest_metadata" in entity_json:
        # This if block should catch primary datasets because primary datasets should
        # have their metadata ingested as part of the reorganization.
        if "metadata" in entity_json and not isinstance(entity_json["metadata"], list):
            metadata = entity_json["metadata"]
        else:
            # If there is no ingest-metadata, then it must be a derived dataset
            metadata["data_types"] = calculate_data_types(entity_json)

        dag_prov_list = [
            elt['origin'] + ':' + elt['name']
            for elt in entity_json["ingest_metadata"].get('dag_provenance_list', [])
            if 'origin' in elt and 'name' in elt
        ]

        # In the case of Publications, we must also set the data_types.
        # The primary publication will always have metadata,
        # so we have to do the association here.
        if entity_json["entity_type"] == "Publication":
            metadata["data_types"] = calculate_data_types(entity_json)

    # If there is no ingest_metadata, then it must be a derived dataset
    else:
        metadata["data_types"] = calculate_data_types(entity_json)

    metadata["entity_type"] = entity_json["entity_type"]
    if metadata["entity_type"].upper() in ["DONOR", "SAMPLE"]:
        raise ValueError(f"Entity is a {metadata['entity_type']}")
    metadata["dag_provenance_list"] = dag_prov_list
    metadata["creation_action"] = entity_json.get("creation_action")

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
        entity_json = get_entity_json(ds_uuid)
        metadata = build_entity_metadata(entity_json)
        is_human = source_is_human(
            [ds_uuid],
            get_entity_json
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
    except HTTPException as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: " + hte.get_description(),
            hte.get_status_code(),
        )
    except urllib.error.HTTPError as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: {hte}",
            hte.status,
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500
        )


@bp.route("/assaytype/metadata/<ds_uuid>", methods=["GET"])
def get_ds_rule_metadata(ds_uuid: str):
    try:
        entity_json = get_entity_json(ds_uuid)
        metadata = build_entity_metadata(entity_json)
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
    except HTTPException as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: " + hte.get_description(),
            hte.get_status_code(),
        )
    except urllib.error.HTTPError as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: {hte}",
            hte.status,
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
    except HTTPException as hte:
        return Response(
            f"Error while getting assay type from metadata: " + hte.get_description(),
            hte.get_status_code(),
        )
    except urllib.error.HTTPError as hte:
        return Response(
            f"Error while getting assay type from metadata: {hte}",
            hte.status,
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while getting assay type from metadata: " + str(e), 500
        )


@bp.route("/reload-assaytypes", methods=["PUT"])
def reload_chain():
    try:
        initialize_rule_chains()
        return jsonify({})
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except (RuleSyntaxException, RuleLogicException) as excp:
        return Response(f"Error applying classification rules: {excp}", 500)
    except HTTPException as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while reloading rule chain: " + str(e), 500)
