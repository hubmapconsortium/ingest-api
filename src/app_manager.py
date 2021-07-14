import logging
import requests
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from flask import jsonify, json, Response

# Local modules
from dataset import Dataset
from dataset_helper_object import DatasetHelper
from api.entity_api import EntityApi
from file_upload_helper import UploadFileHelper

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)


def nexus_token_from_request_headers(request_headers: object) -> str:
    bearer_token = request_headers['AUTHORIZATION'].strip()
    nexus_token = bearer_token[len('bearer '):].strip()
    return nexus_token


def update_ingest_status_title_thumbnail(app_config: object, request_json: object, 
                                         request_headers: object, entity_api: EntityApi, 
                                         file_upload_helper_instance: UploadFileHelper) -> object:
    dataset_uuid = request_json['dataset_id'].strip()
    nexus_token = nexus_token_from_request_headers(request_headers)
    dataset = Dataset(app_config)
    dataset_helper = DatasetHelper()

    # Headers for calling entity-api via PUT to update Dataset.status
    extra_headers = {
        'Content-Type': 'application/json', 
        'X-Hubmap-Application': 'ingest-api'
    }

    # updated_ds is the dict returned by ingest-pipeline, not the complete entity information
    # Note: 'dataset_id' is in request_json but not in the resulting updated_ds
    updated_ds = dataset.get_dataset_ingest_update_record(request_json)

    logger.debug('=======get_dataset_ingest_update_record=======')
    logger.debug(updated_ds)

    # For thumbnail image handling if ingest-pipeline finds the file
    # and sends the absolute file path back
    if 'thumbnail_file_abs_path' in updated_ds:
        try:
            # Generate a temp file id and copy the source file to the temp upload dir
            temp_file_id = file_upload_helper_instance.get_temp_file_id()

            updated_ds = dataset_helper.handle_thumbnail_file(updated_ds, 
                                                              entity_api, 
                                                              dataset_uuid, 
                                                              extra_headers, 
                                                              temp_file_id, 
                                                              file_upload_temp_dir)
        except requests.exceptions.RequestException as e:
            msg = e.response.text 
            logger.exception(msg)

            # Due to the use of response.raise_for_status() in schema_manager.create_hubmap_ids()
            # we can access the status codes from the exception
            return Response(msg, e.response.status_code)

    response = entity_api.put_entities(dataset_uuid, updated_ds, extra_headers)

    if response.status_code != 200:
        err_msg = f"Error while updating the dataset status using EntityApi.put_entities() status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        logger.error("Sent: " + json.dumps(updated_ds))
        return Response(response.text, response.status_code)
    
    # The PUT call returns the latest dataset...
    lastest_dataset = response.json()
    
    logger.debug('=======lastest_dataset before title update=======')
    logger.debug(lastest_dataset)

    if lastest_dataset['status'].upper() == 'QA':
        # Update only the title and save...
        updated_title = {'title': dataset_helper.generate_dataset_title(lastest_dataset, nexus_token)}
        response = entity_api.put_entities(dataset_uuid, updated_title)
        if response.status_code != 200:
            err_msg = f"Error while updating the dataset title using EntityApi.put_entities() status code:{response.status_code}  message:{response.text}"
            logger.error(err_msg)
            logger.error("Sent: " + json.dumps(updated_title))
            return Response(response.text, response.status_code)

    final_dataset = response.json()

    logger.debug('=======final_dataset after title update=======')
    logger.debug(final_dataset)

    return jsonify({'result': final_dataset}), response.status_code


def verify_dataset_title_info(uuid: str, request_headers: object) -> object:
    nexus_token = nexus_token_from_request_headers(request_headers)
    dataset_helper = DatasetHelper()
    return dataset_helper.verify_dataset_title_info(uuid, nexus_token)

