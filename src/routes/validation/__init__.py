import sys
import os
import time
import csv
import logging
from typing import Union
from flask import Blueprint, current_app, Response
import json
import requests

from importlib import import_module

from routes.validation.lib.file import get_csv_records, get_base_path, check_upload, ln_err

from hubmap_commons import file_helper as commons_file_helper
from hubmap_commons.hm_auth import AuthHelper

from atlas_consortia_commons.rest import *
from atlas_consortia_commons.string import equals, to_title_case


# Need to install Git submodule ingest_validation_tools
# $ cd project-top-level
# $ git submodule add -b phillips/cedar_tests --name ingest_validation_tools  https://github.com/hubmapconsortium/ingest-validation-tools src/routes/validation/ingest_validation_tools
# To update....
# $ git submodule update --init --remote
# AND THEN...
# $ pip install -r src/routes/validation/ingest_validation_tools/requirements.txt

sys.path.append(os.path.join(os.path.dirname(__file__), 'ingest_validation_tools', 'src'))

ingest_validation_tools_upload = import_module('ingest_validation_tools.upload')
ingest_validation_tools_error_report = import_module('ingest_validation_tools.error_report')
ingest_validation_tools_validation_utils = import_module('ingest_validation_tools.validation_utils')
ingest_validation_tools_plugin_validator = import_module('ingest_validation_tools.plugin_validator')
ingest_validation_tools_schema_loader = import_module('ingest_validation_tools.schema_loader')
ingest_validation_tools_table_validator = import_module('ingest_validation_tools.table_validator')

__all__ = ["ingest_validation_tools_upload",
           "ingest_validation_tools_error_report",
           "ingest_validation_tools_validation_utils",
           "ingest_validation_tools_plugin_validator",
           "ingest_validation_tools_schema_loader",
           "ingest_validation_tools_table_validator"
           ]


validation_blueprint: Blueprint = Blueprint('validation', __name__)

logger: logging.Logger = logging.getLogger(__name__)


def get_groups_token() -> str:
    return request.headers.get('authorization')[7:]


def check_metadata_upload():
    """
    Checks the uploaded file

    Returns dict containing upload details or an 'error' key if something went wrong
    """
    result: dict = {
        'error': None
    }
    file_upload = check_upload('metadata')
    if file_upload.get('code') is StatusCodes.OK:
        file = file_upload.get('description')
        file_id = file.get('id')
        file = file.get('file')
        pathname = file_id + os.sep + file.filename
        result = set_file_details(pathname)
    else:
        result['error'] = file_upload

    return result


def set_file_details(pathname: str):
    """
    Creates a dictionary of file and path details

    Parameters
    ----------
    pathname str pathname

    Returns dict containing the filename and fullpath details
    """
    base_path = get_base_path()
    return {
        'pathname': pathname,
        'fullpath': base_path + pathname
    }


def get_metadata(path: str) -> list:
    """
    Parses a tsv and returns the rows of that tsv

    Parameters
    ----------
    path str path where the tsv file is stored

    Returns list of dictionaries
    """
    result = get_csv_records(path)
    return result.get('records')


def validate_tsv(schema='metadata', path=None) -> str:
    """
    Calls methods of the Ingest Validation Tools submodule

    Parameters
    ----------
    schema str name of the schema to validate against
    path str path of the tsv for Ingest Validation Tools

    Returns str json formatted dict containing validation results
    """
    auth_helper_instance: AuthHelper = AuthHelper.instance()
    auth_helper_instance: AuthHelper = AuthHelper.instance()

    try:
        schema_name = (
            schema if schema != 'metadata'
            else ingest_validation_tools_validation_utils.get_schema_version(path, 'ascii', globus_token=globus_token).schema_name
        )
    except ingest_validation_tools_schema_loader.PreflightError as e:
        result = {'Preflight': str(e)}
    else:
        try:
            report_type = ingest_validation_tools_table_validator.ReportType.JSON
            result = ingest_validation_tools_validation_utils\
                .get_tsv_errors(path, schema_name=schema_name, report_type=report_type, globus_token=globus_token)
        except Exception as e:
            result = rest_server_err(e, True)
    return json.dumps(result)


def create_tsv_from_path(path: str, row: int) -> dict:
    """
    Creates a tsv from path of a specific row. This is in order to validate only one if necessary.

    Parameters
    ----------
    path str ath of original tsv
    row int row number in tsv to extract for new tsv

    Returns dict containing file details
    """
    try:
        records = get_csv_records(path, records_as_arr=True)
        result = set_file_details(f"{time.time()}.tsv")

        with open(result.get('fullpath'), 'wt') as out_file:
            tsv_writer = csv.writer(out_file, delimiter='\t')
            tsv_writer.writerow(records.get('headers'))
            tsv_writer.writerow(records.get('records')[row])
    except Exception as e:
        result = rest_server_err(e, True)

    return result


def get_cedar_schema_ids() -> dict:
    return {
        'Block': '3e98cee6-d3fb-467b-8d4e-9ba7ee49eeff',
        'Section': '01e9bc58-bdf2-49f4-9cf9-dd34f3cc62d7',
        'Suspension': 'ea4fb93c-508e-4ec4-8a4b-89492ba68088'
    }


def check_cedar(entity_type: str, sub_type, upload) -> bool:
    records = get_metadata(upload.get('fullpath'))
    if len(records) > 0:
        if equals(entity_type, "Sample") and 'metadata_schema_id' in records[0]:
            cedar_sample_sub_type_ids = get_cedar_schema_ids()
            return equals(records[0]['metadata_schema_id'], cedar_sample_sub_type_ids[sub_type])
    return True


def determine_schema(entity_type: str, sub_type) -> Union[dict, Response, str]:
    if equals(entity_type, "Sample"):
        if not sub_type:
            return rest_bad_req("`sub_type` for schema name required.")
        schema = f"sample-{sub_type}"
    else:
        schema = 'metadata'

    schema = schema.lower()
    return schema


def _get_response(metadata, entity_type, sub_type, validate_uuids, pathname=None) -> dict:
    if validate_uuids == '1':
        response = validate_records_uuids(metadata, entity_type, sub_type, pathname)
    else:
        response = {
            'code': StatusCodes.OK,
            'pathname': pathname,
            'metadata': metadata
        }

    return response


def get_col_id_name_by_entity_type(entity_type: str) -> str:
    """
    Returns the tsv id column name for the given entity type

    Parameters
    ----------
    entity_type str entity type

    Returns st name of the column in the tsv
    """
    if equals(entity_type, 'Sample'):
        return 'sample_id'
    else:
        return 'source_id'


def get_sub_type_name_by_entity_type(entity_type: str) -> str:
    if equals(entity_type, 'Sample'):
        return 'sample_category'
    else:
        return 'source_type'


def supported_metadata_sub_types(entity_type: str) -> list:
    if equals(entity_type, 'Source'):
        return ['Human']
    else:
        return ["Block", "Section", "Suspension"]


def validate_records_uuids(records: list, entity_type: str, sub_type, pathname: str):
    """
    Validates the uuids of given records.
    This is used for bulk upload so that ancestor ids referenced by the user in TSVs
    are found to actually exist, are supported and confirm to entity constraints.

    Parameters
    ----------
    records list of records to validate
    entity_type stt entity type
    sub_type str sub-type of the entity
    pathname str pathname of the tsv; always returned in the response for tracking and other re-validation

    Returns Rest response containing results of validation
    -------

    """
    errors = []
    passing = []
    ok = True
    idx = 1
    for r in records:
        # First get the id column name, in order to get the id in the record
        id_col = get_col_id_name_by_entity_type(entity_type)
        entity_id = r.get(id_col)
        entity_url: str = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL'])
        auth_helper_instance: AuthHelper = AuthHelper.instance()
        token = auth_helper_instance.getAuthorizationTokens(request.headers)
        resp = requests.get(f'{entity_url}entities/{entity_id}',
                            headers={f'Authorization: Bearer {token}',
                                     'X-Application: ingest-api'})
        if resp.status_code < 300:
            entity = resp.json()
            if sub_type is not None:
                sub_type_col = get_sub_type_name_by_entity_type(entity_type)
                _sub_type = entity.get(sub_type_col)
                if _sub_type not in supported_metadata_sub_types(entity_type):
                    ok = False
                    errors.append(rest_response(StatusCodes.UNACCEPTABLE, StatusMsgs.UNACCEPTABLE,
                                                ln_err(f"of `{to_title_case(_sub_type)}` unsupported "
                                                       f"on check of given `{entity_id}`. "
                                                       f"Supported `{'`, `'.join(supported_metadata_sub_types(entity_type))}`.",
                                                       idx, sub_type_col), dict_only=True))
                # Check that the stored entity _sub_type matches what is expected (the type being bulk uploaded)
                elif not equals(sub_type, _sub_type):
                    ok = False
                    errors.append(rest_response(
                        StatusCodes.UNACCEPTABLE,
                        StatusMsgs.UNACCEPTABLE,
                        ln_err(f"got `{to_title_case(_sub_type)}` on check of given `{entity_id}`, "
                               f"expected `{sub_type}` for `{sub_type_col}`.", idx, id_col),
                        dict_only=True))
                else:
                    entity['metadata'] = r
                    passing.append(rest_ok(entity, True))
            else:
                entity['metadata'] = r
                passing.append(rest_ok(entity, True))
        else:
            ok = False
            errors.append(rest_response(StatusCodes(resp.status_code), StatusMsgs.UNACCEPTABLE,
                                        ln_err(f"invalid `{id_col}`: '{entity_id}'", idx, id_col),
                                        dict_only=True))
        idx += 1

    if ok is True:
        return rest_ok({'data': passing, 'pathname': pathname},
                       dict_only=True)
    else:
        return rest_response(StatusCodes.UNACCEPTABLE,
                             'There are invalid `uuids` and/or unmatched entity sub types', errors,
                             dict_only=True)


@validation_blueprint.route('/metadata/validate', methods=['POST'])
def validate_metadata_upload():
    try:
        if is_json_request():
            data = request.json
        else:
            data = request.values

        pathname = data.get('pathname')
        entity_type = data.get('entity_type')
        sub_type = data.get('sub_type')
        validate_uuids = data.get('validate_uuids')
        tsv_row = data.get('tsv_row')

        if pathname is None:
            upload = check_metadata_upload()
        else:
            if tsv_row is None:
                upload = set_file_details(pathname)
            else:
                upload = create_tsv_from_path(get_base_path() + pathname, int(tsv_row))

        error = upload.get('error')
        response = error

        if error is None:
            if check_cedar(entity_type, sub_type, upload) is False:
                id_sub_type = get_cedar_schema_ids().get(sub_type)
                return rest_response(StatusCodes.UNACCEPTABLE,
                                     'Unacceptable Metadata',
                                     f"Mismatch of \"{entity_type} {sub_type}\" and \"metadata_schema_id\". "
                                     f"Valid id for \"{sub_type}\": {id_sub_type}. "
                                     "For more details, check out the docs: "
                                     "https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas")
            path: str = upload.get('fullpath')
            schema = determine_schema(entity_type, sub_type)
            validation_results = validate_tsv(path=path, schema=schema)
            if len(validation_results) > 2:
                response = rest_response(StatusCodes.UNACCEPTABLE, 'Unacceptable Metadata',
                                         json.loads(validation_results), True)
            else:
                records = get_metadata(upload.get('fullpath'))
                response = _get_response(records, entity_type, sub_type, validate_uuids,
                                         pathname=upload.get('pathname'))
                if tsv_row is not None:
                    os.remove(upload.get('fullpath'))

    except Exception as e:
        response = rest_server_err(e, True)

    return full_response(response)
