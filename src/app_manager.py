import logging
import requests
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from flask import json
from pathlib import Path
from shutil import copy2

# Local modules
from dataset import Dataset
from dataset_helper_object import DatasetHelper
from api.entity_api import EntityApi

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)


def nexus_token_from_request_headers(request_headers: object) -> str:
    bearer_token = request_headers['AUTHORIZATION'].strip()
    nexus_token = bearer_token[len('bearer '):].strip()
    return nexus_token


def update_ingest_status(app_config: object, request_json: object, request_headers: object, logger: object) -> object:
    dataset = Dataset(app_config)
    logger.info("++++++++++Calling /datasets/status")
    logger.info("++++++++++Request:" + json.dumps(request_json))
    # expecting something like this:
    # {'dataset_id' : '287d61b60b806fdf54916e3b7795ad5a', 'status': '<', 'message': 'the process ran', 'metadata': [maybe some metadata stuff], 'thumbnail_image_abs_path': 'full path to the image'}}
    updated_ds = dataset.get_dataset_ingest_update_record(request_json)

    if updated_ds['status'].upper() == 'QA':
        # Update the title
        nexus_token = nexus_token_from_request_headers(request_headers)
        dataset_helper = DatasetHelper()
        updated_ds['title'] = dataset_helper.generate_dataset_title(updated_ds, nexus_token)

    return updated_ds


def verify_dataset_title_info(uuid: str, request_headers: object) -> object:
    nexus_token = nexus_token_from_request_headers(request_headers)
    dataset_helper = DatasetHelper()
    return dataset_helper.verify_dataset_title_info(uuid, nexus_token)


def handle_thumbnail_file(entity_api: object, dataset_uuid: str, extra_headers: object, file_upload_helper_instance: object, file_upload_temp_dir: str):
    # Delete the old thumbnail file from Neo4j before updating with new one
    # First retrieve the exisiting thumbnail file uuid
    response = entity_api.get_entities(dataset_uuid)
    if response.status_code != 200:
        err_msg = f"Failed to query the dataset of uuid {dataset_uuid} while calling EntityApi.get_entities() status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        return Response(response.text, response.status_code)

    entity_dict = response.json()

    # Easier to ask for forgiveness than permission (EAFP)
    # Rather than checking key existence at every level
    try:
        thumbnail_file_uuid = entity_dict['thumbnail_file']['file_uuid']

        # To remove the existing thumbnail file, just pass the file uuid as a string
        put_data = {
            'thumbnail_file_to_remove': thumbnail_file_uuid
        }

        response = entity_api.put_entities(dataset_uuid, put_data, extra_headers)
        if response.status_code != 200:
            err_msg = f"Failed to remove the existing thumbnail file for dataset of uuid {dataset_uuid} while calling EntityApi.put_entities() status code:{response.status_code}  message:{response.text}"
            logger.error(err_msg)
            return Response(response.text, response.status_code)

        logger.debug(f"Successfully removed the existing thumbnail file of the dataset uuid {dataset_uuid}")
    except KeyError:
        logger.debug(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
        pass

    # All steps on updaing with this new thumbnail
    thumbnail_file_abs_path = updated_ds['thumbnail_file_abs_path']

    # Generate a temp file id and copy the source file to the temp upload dir
    temp_file_id = file_upload_helper_instance.get_temp_file_id()

    logger.debug(f"temp_file_id created for thumbnail file: {temp_file_id}")

    # Create the temp file dir under the temp uploads for the thumbnail
    # /hive/hubmap/hm_uploads_tmp/<temp_file_id> (for PROD)
    temp_file_dir = os.path.join(file_upload_temp_dir, temp_file_id)
    
    try:
        Path(temp_file_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.exception(f"Failed to create the thumbnail temp upload dir {temp_file_dir} for thumbnail file attched to Dataset {result_json['uuid']}")

    # Then copy the source thumbnail file to the temp file dir
    # shutil.copy2 is identical to shutil.copy() method
    # but it also try to preserves the file's metadata
    copy2(thumbnail_file_abs_path, temp_file_dir)

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

    # Remove the 'thumbnail_file_abs_path' property 
    # since it's not defined in entity-api schema
    updated_ds.pop('thumbnail_file_abs_path')

    return updated_ds