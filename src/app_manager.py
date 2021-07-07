from flask import json
from dataset import Dataset
from dataset_helper_object import DatasetHelper


def nexus_token_from_request_headers(request_headers: object) -> str:
    bearer_token = request_headers['AUTHORIZATION'].strip()
    nexus_token = bearer_token[len('bearer '):].strip()
    return nexus_token


def update_ingest_status(app_config: object, request_json: object, request_headers: object, logger: object) -> object:
    dataset = Dataset(app_config)
    logger.info("++++++++++Calling /datasets/status")
    logger.info("++++++++++Request:" + json.dumps(request_json))
    # expecting something like this:
    # {'dataset_id' : '287d61b60b806fdf54916e3b7795ad5a', 'status': '<', 'message': 'the process ran', 'metadata': [maybe some metadata stuff]}
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
