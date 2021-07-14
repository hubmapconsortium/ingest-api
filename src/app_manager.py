from flask import jsonify, json, Response
from dataset import Dataset
from dataset_helper_object import DatasetHelper
from api.entity_api import EntityApi
import logging

logger = logging.getLogger(__name__)


def nexus_token_from_request_headers(request_headers: object) -> str:
    bearer_token = request_headers['AUTHORIZATION'].strip()
    nexus_token = bearer_token[len('bearer '):].strip()
    return nexus_token


def update_ingest_status_and_title(app_config: object, request_json: object, request_headers: object, entity_api: EntityApi) -> object:
    dataset_uuid = request_json['dataset_id'].strip()
    nexus_token = nexus_token_from_request_headers(request_headers)
    dataset = Dataset(app_config)
    dataset_helper = DatasetHelper()

    updated_ds = dataset.get_dataset_ingest_update_record(request_json)

    logger.debug('=======get_dataset_ingest_update_record=======')
    logger.debug(updated_ds)

    response = entity_api.put_entities(dataset_uuid, updated_ds)
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
