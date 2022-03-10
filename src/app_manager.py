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


def groups_token_from_request_headers(request_headers: object) -> str:
    bearer_token = request_headers['AUTHORIZATION'].strip()
    groups_token = bearer_token[len('bearer '):].strip()
    return groups_token


def update_ingest_status_title_thumbnail(app_config: object, request_json: object, 
                                         request_headers: object, entity_api: EntityApi, 
                                         file_upload_helper_instance: UploadFileHelper) -> object:
    dataset_uuid = request_json['dataset_id'].strip()
    dataset = Dataset(app_config)
    dataset_helper = DatasetHelper()

    # Headers for calling entity-api via PUT to update Dataset.status
    extra_headers = {
        'Content-Type': 'application/json', 
        'X-Hubmap-Application': 'ingest-api'
    }

    # updated_ds is the dict returned by ingest-pipeline, not the complete entity information
    # Note: 'dataset_id' is in request_json but not in the resulting updated_ds
    # request_json['thumbnail_file_abs_path'] is converted to updated_ds['ingest_metadata']['thumbnail_file_abs_path']
    updated_ds = dataset.get_dataset_ingest_update_record(request_json)

    logger.debug('=======get_dataset_ingest_update_record=======')
    logger.debug(updated_ds)

    # For thumbnail image handling if ingest-pipeline finds the file
    # and sends the absolute file path back 
    try:
        thumbnail_file_abs_path = updated_ds['ingest_metadata']['thumbnail_file_abs_path']

        logger.debug("=======thumbnail_file_abs_path found=======")

        # Generate a temp file id and copy the source file to the temp upload dir
        temp_file_id = file_upload_helper_instance.get_temp_file_id()
        file_upload_temp_dir = file_upload_helper_instance.upload_temp_dir

        try:
            dataset_helper.handle_thumbnail_file(thumbnail_file_abs_path, 
                                                 entity_api, 
                                                 dataset_uuid, 
                                                 extra_headers, 
                                                 temp_file_id, 
                                                 file_upload_temp_dir)

            # Now add the thumbnail file by making a call to entity-api
            # And the entity-api will execute the trigger method defined
            # for the property 'thumbnail_file_to_add' to commit this
            # file via ingest-api's /file-commit endpoint, which treats
            # the temp file as uploaded file and moves it to the generated file_uuid
            # dir under the upload dir: /hive/hubmap/hm_uploads/<file_uuid> (for PROD)
            # and also creates the symbolic link to the assets
            updated_ds['thumbnail_file_to_add'] = {
                'temp_file_id': temp_file_id
            }
        except requests.exceptions.RequestException as e:
            msg = e.response.text 
            logger.exception(msg)

            # Due to the use of response.raise_for_status() in schema_manager.create_hubmap_ids()
            # we can access the status codes from the exception
            return Response(msg, e.response.status_code)
    except KeyError:
        logger.info(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
        pass

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

    return jsonify({'result': lastest_dataset}), response.status_code


def verify_dataset_title_info(uuid: str, request_headers: object) -> object:
    groups_token = groups_token_from_request_headers(request_headers)
    dataset_helper = DatasetHelper()
    return dataset_helper.verify_dataset_title_info(uuid, groups_token)

